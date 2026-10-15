local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Scans MQTT brokers (port 1883/8883) for unauthenticated access by
performing a real MQTT CONNECT handshake and reading the CONNACK return
code, then scanning for encryption and topic-level data exposure via
subscription attempts.

Unlike mqtt-subscribe.nse (which enumerates by dumping live message
traffic once connected), this script scans for and reports several
specific conditions in a single pass: authentication requirement,
encryption status, and whether client/broker topics are readable.

Each check is reported individually as found/not found. This script does
not combine results into an aggregate score -- it is a detection scan,
not a compliance assessment.

Checks performed:
  1. CONNACK return code (0x00 = accepted with no authentication)
  2. Port/encryption (1883 plaintext vs 8883 TLS)
  3. Wildcard subscribe "#" (all client topics)
  4. "$SYS/#" subscribe (broker internal metadata)

Script arguments:
  mqtt-exposure-scanner.topic  : an additional custom topic to test
  Example:
  nmap -p1883 --script mqtt-exposure-scanner
       --script-args mqtt-exposure-scanner.topic=sensors/kitchen <target>
]]

author = "Dhriti"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service({1883, 8883}, {"mqtt", "secure-mqtt"}, "tcp")

local function build_connect_packet(client_id)
  local protocol_name = "\x00\x04MQTT"
  local protocol_level = "\x04"
  local connect_flags  = "\x02"
  local keepalive      = "\x00\x3c"
  local client_id_field = string.pack(">I2", #client_id) .. client_id
  local variable_header = protocol_name .. protocol_level .. connect_flags .. keepalive
  local payload = client_id_field
  local remaining = variable_header .. payload
  local remaining_length = string.char(#remaining)
  return "\x10" .. remaining_length .. remaining
end

local function build_subscribe_packet(topic, packet_id)
  local topic_field = string.pack(">I2", #topic) .. topic .. "\x00"
  local variable_header = string.pack(">I2", packet_id)
  local remaining = variable_header .. topic_field
  return "\x82" .. string.char(#remaining) .. remaining
end

local function try_connect(host, port, client_id)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  local ok, err = sock:connect(host, port)
  if not ok then return nil, "connect failed: " .. tostring(err) end

  local packet = build_connect_packet(client_id)
  sock:send(packet)

  local status, response = sock:receive_bytes(4)
  if not status then
    sock:close()
    return nil, "no CONNACK received"
  end

  local return_code = response:byte(4)
  return sock, return_code
end

action = function(host, port)
  local custom_topic = stdnse.get_script_args(SCRIPT_NAME .. ".topic")

  local client_id = "nmap-" .. tostring(math.random(10000, 99999))
  local sock, return_code = try_connect(host, port, client_id)

  if not sock then
    return stdnse.format_output(false, "Could not complete MQTT handshake: " .. tostring(return_code))
  end

  local output = {}

  -- Check 1: authentication
  if return_code == 0x00 then
    table.insert(output, "Authentication required : NO -- broker accepted connection with no credentials (CONNACK 0x00)")
  else
    sock:close()
    table.insert(output, ("Authentication required : YES -- broker rejected connection (CONNACK 0x%02x)"):format(return_code))
    return stdnse.format_output(true, output)
  end

  -- Check 2: encryption
  if port.number == 1883 then
    table.insert(output, "Encryption : NONE -- plaintext port 1883 in use")
  else
    table.insert(output, "Encryption : TLS port in use")
  end

  -- Check 3: wildcard topic subscribe
  local sub_all = build_subscribe_packet("#", 1)
  sock:send(sub_all)
  local s1, resp1 = sock:receive_bytes(1)
  if s1 and resp1 and resp1:byte(1) == 0x90 then
    table.insert(output, "Client topics ('#') readable : YES -- subscription to all client topics accepted")
  else
    table.insert(output, "Client topics ('#') readable : NO / undetermined")
  end

  -- Check 4: broker internal metadata
  local sub_sys = build_subscribe_packet("$SYS/#", 2)
  sock:send(sub_sys)
  local s2, resp2 = sock:receive_bytes(1)
  if s2 and resp2 and resp2:byte(1) == 0x90 then
    table.insert(output, "Broker internals ('$SYS/#') readable : YES -- version/uptime/client-count metadata exposed")
  else
    table.insert(output, "Broker internals ('$SYS/#') readable : NO / undetermined")
  end

  -- Optional: custom topic supplied via script-args
  if custom_topic then
    local sub_custom = build_subscribe_packet(custom_topic, 3)
    sock:send(sub_custom)
    local s3, resp3 = sock:receive_bytes(1)
    if s3 and resp3 and resp3:byte(1) == 0x90 then
      table.insert(output, ("Custom topic ('%s') readable : YES"):format(custom_topic))
    else
      table.insert(output, ("Custom topic ('%s') readable : NO / undetermined"):format(custom_topic))
    end
  end

  sock:close()

  return stdnse.format_output(true, output)
end
