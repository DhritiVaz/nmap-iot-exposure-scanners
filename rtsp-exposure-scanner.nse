local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Scans RTSP camera streams (port 554) for unauthenticated access by
performing an OPTIONS -> DESCRIBE handshake against common stream paths,
then scanning for encryption status and stream confirmation.

Unlike rtsp-methods.nse (lists supported commands) or rtsp-url-brute.nse
(enumerates valid stream URLs from a wordlist), this script scans for and
reports several specific conditions in a single pass: authentication
requirement, encryption status, and whether a genuine live stream was
confirmed.

Each check is reported individually as found/not found. This script does
not combine results into an aggregate score -- it is a detection scan,
not a compliance assessment.

Checks performed:
  1. DESCRIBE response code (200 = accessible with no authentication)
  2. Port/encryption (554 plaintext vs RTSPS)
  3. SDP body presence (confirms a genuine live stream)
  4. Path used to reach the stream (built-in guess list, or a supplied path)

Script arguments:
  rtsp-exposure-scanner.path  : a specific stream path to test first
  Example:
  nmap -p554 --script rtsp-exposure-scanner
       --script-args rtsp-exposure-scanner.path=/cam1 <target>
]]

author = "Dhriti"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(554, "rtsp", "tcp")

local COMMON_PATHS = {"/", "/live", "/stream1", "/live.sdp", "/video", "/cam", "/media"}

local function rtsp_request(host, port, method, url, cseq, extra_headers)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok, err = sock:connect(host, port)
  if not ok then
    return nil, "connect failed: " .. tostring(err)
  end

  local req = ("%s %s RTSP/1.0\r\nCSeq: %d\r\n"):format(method, url, cseq)
  if extra_headers then
    req = req .. extra_headers
  end
  req = req .. "\r\n"

  local send_ok = sock:send(req)
  if not send_ok then
    sock:close()
    return nil, "send failed"
  end

  local status, response = sock:receive()
  sock:close()

  if not status then
    return nil, "no response received"
  end
  return response
end

local function parse_status_code(response)
  if not response then return nil end
  local code = response:match("RTSP/1%.0%s+(%d+)")
  return code and tonumber(code) or nil
end

action = function(host, port)
  local base_url = ("rtsp://%s:%d"):format(host.ip, port.number)
  local output = {}
  local cseq = 1

  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_try = {}
  if custom_path then
    table.insert(paths_to_try, custom_path)
  end
  for _, p in ipairs(COMMON_PATHS) do
    table.insert(paths_to_try, p)
  end

  -- Step 1: OPTIONS -- confirm this is really an RTSP server before DESCRIBE
  local opt_resp, opt_err = rtsp_request(host, port, "OPTIONS", base_url .. "/", cseq)
  cseq = cseq + 1
  local opt_code = parse_status_code(opt_resp)
  if not opt_code then
    return stdnse.format_output(false, "No valid RTSP OPTIONS response: " .. tostring(opt_err))
  end
  table.insert(output, ("OPTIONS response : RTSP/1.0 %d"):format(opt_code))

  -- Step 2: DESCRIBE against the path list (custom path first, if supplied)
  local found_path, describe_code, describe_body
  for _, path in ipairs(paths_to_try) do
    local url = base_url .. path
    local resp = rtsp_request(host, port, "DESCRIBE", url, cseq, "Accept: application/sdp\r\n")
    cseq = cseq + 1
    local code = parse_status_code(resp)
    if code == 200 then
      found_path = path
      describe_code = code
      describe_body = resp
      break
    elseif code == 401 and not describe_code then
      describe_code = code
    end
  end

  -- Check 1: authentication
  if describe_code == 200 then
    table.insert(output, ("Authentication required : NO -- stream accessible at path '%s' (200 OK)"):format(found_path))
  elseif describe_code == 401 then
    table.insert(output, "Authentication required : YES -- stream returned 401 Unauthorized")
    return stdnse.format_output(true, output)
  else
    table.insert(output, "Stream found : NO -- no accessible path found among tested paths")
    return stdnse.format_output(true, output)
  end

  -- Check 2: encryption
  if port.number == 554 then
    table.insert(output, "Encryption : NONE -- plain RTSP, port 554")
  else
    table.insert(output, "Encryption : RTSPS in use")
  end

  -- Check 3: stream confirmation
  if describe_body and describe_body:find("v=0") then
    table.insert(output, "Stream confirmed : YES -- valid SDP body present (genuine live stream)")
  else
    table.insert(output, "Stream confirmed : DESCRIBE succeeded but no SDP body detected")
  end

  -- Check 4: path used
  table.insert(output, ("Path used to reach stream : '%s'"):format(found_path))

  return stdnse.format_output(true, output)
end
