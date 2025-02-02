-- do not modify this table
local debug_level = {DISABLED = 0, LEVEL_1 = 1, LEVEL_2 = 2}

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings = {
    debug_level = debug_level.LEVEL_2,
    port = 9876 -- default TCP port number for usbmux
}

local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...) print(table.concat({"Lua: ", ...}, " ")) end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()

usbmux_protocol = Proto("usbmux", "Apple USBMUX Protocol")

DissectorTable.new("usbmux.subproto")

local usbmuxd_msgtypes = {
    "result", "connect", "listen", "device_add", "device_remove",
    "device_paired", "unknown", "plist"
}
-- https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
local tls_content_type = {
    ["change_cipher_spec"] = 20,
    ["alert"] = 21,
    ["handshake"] = 22,
    ["application_data"] = 23,
    ["heartbeat"] = 24,
    ["tls12_cid"] = 25,
    ["AC"] = 26
}

local header_fields = {

    message_length = ProtoField.uint32("usbmux.message_length",
                                       "message_length", base.DEC),
    version = ProtoField.int32("usbmux.version", "version", base.DEC),
    message_type = ProtoField.int32("usbmux.message_type", "message_type",
                                    base.DEC, usbmuxd_msgtypes),
    tag = ProtoField.int32("usbmux.tag", "tag", base.DEC),
    payload = ProtoField.string("usbmux.payload", "payload")
    -- lockdownd = ProtoField.bool("usbmux.lockdownd", "is lockdownd frame"),
    -- tls = ProtoField.bool("usbmux.tls", "is TLS")
}

-- register the ProtoFields
usbmux_protocol.fields = header_fields

local sub_dissectors = {}
local tcp_steam = Field.new("tcp.stream")
-- local usbmux_tls = Field.new("usbmux.tls")

function usbmux_protocol.init()
    tls_dissector = Dissector.get("tls")
    plist_dissector = Dissector.get("plist")
    lockdown_dissector = Dissector.get("lockdown")
    dtxmessage_dissector = Dissector.get("dtxmessage")
end

local USBMUX_MSG_HDR_LEN = 4
local TLS_MSG_HDR_LEN = 5

checkUsbmuxLength = function(tvbuf, offset)
    -- "remainlen" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local remainlen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if remainlen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        dprint2("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if remainlen < math.max(USBMUX_MSG_HDR_LEN, TLS_MSG_HDR_LEN) then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        dprint2("Need more bytes to figure out Usbmux length field")
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this Usbmux messsage

    local msgLen
    local sub_dissector
    -- todo: should only enter once?
    -- local inside_tls = usbmux_tls()
    -- dprint2("inside_tls", inside_tls)
    -- local tcp_stream_id = tcp_steam().value
    -- local start_pktnum = tls_started[tcp_stream_id]
    -- dprint2("tcp_stream_id", tcp_stream_id, "start_pktnum", start_pktnum,
    --       "pinfo.number", pinfo.number)

    print(tvbuf(offset, 4):le_uint())
    if -- start_pktnum and pinfo.number >= start_pktnum or
    tls_content_type["change_cipher_spec"] <= tvbuf(offset, 1):uint() and
        tvbuf(offset, 1):uint() <= tls_content_type['AC'] and
        (tvbuf(offset + 1, 2):uint() == 0x0301 or tvbuf(offset + 1, 2):uint() ==
            0x0303) then

        -- subtree:add(header_fields.tls, true)

        -- if pinfo.number < (start_pktnum or 99999) then
        --     tls_started[tcp_stream_id] = pinfo.number
        -- end
        msgLen = 1 + 2 + 2 + tvbuf(offset + 3, 2):uint()
        -- dprint2("tls:", tcp_stream_id, tls_started[tcp_stream_id])

        -- if 1 + 2 + 2 + record_len > tvbuf:len() then
        --     -- reassemble ssl?
        --     dprint2("tls: desegment_len", desegment_len)
        --     pinfo.desegment_len = 1 + 2 + 2 + record_len - tvbuf:len()
        --     pinfo.desegment_offset = 0
        --     return
        -- end

        sub_dissector = tls_dissector
    elseif tvbuf(offset, 4):le_uint() == 0x1F3D5B79 then
        msgLen = 0x20
        sub_dissector = dtxmessage_dissector
    else
        msgLen = tvbuf(offset, 4):le_uint()
        dprint2("plain: msgLen", msgLen)

        -- todo: more test wether is lockdown
        if msgLen > 0xFFFFF then
            -- is_lockdownd = true
            sub_dissector = lockdown_dissector
            msgLen = 4
        end
    end

    if msgLen > remainlen then
        -- we need more bytes to get the whole Usbmux message
        dprint2("Need more bytes to desegment full Usbmux")
        return -(msgLen - remainlen)
    end

    return msgLen, sub_dissector
end

function usbmux_protocol.dissector(tvbuf, pktinfo, root_tree)
    local pktlen = tvbuf:len()
    local bytes_consumed = 0
    dprint("pktlen:", pktlen)

    -- handle split and reassemble
    while bytes_consumed < pktlen do
        local result, sub_dissector = checkUsbmuxLength(tvbuf, bytes_consumed)
        dprint("result1", result, "bytes_consumed", bytes_consumed)

        if result > 0 then
            if sub_dissector then
                dprint2("sub_dissector", tostring(sub_dissector))
                result = sub_dissector(tvbuf, pktinfo, root_tree)
            else
                result = dissect_one_message(tvbuf, pktinfo, root_tree,
                                             bytes_consumed)
            end
        end
        dprint("result2", result)

        if result > 0 then
            bytes_consumed = bytes_consumed + result
            -- go again on another while loop
        elseif result < 0 then
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        else -- if result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        end

        break
    end

    return bytes_consumed
end

function dissect_one_message(tvbuf, pktinfo, root_tree, offset)
    -- tcp stream or inside decrypted tls stream
    -- todo: only once?
    pktinfo.cols.protocol:append('/' .. usbmux_protocol.name)
    local subtree = root_tree:add(usbmux_protocol, tvbuf(),
                                  "USBMUX Protocol Data")

    local payload_length = 0
    msg_length = tvbuf(offset, 4):le_uint()
    subtree:add_le(header_fields.message_length, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.version, tvbuf(offset, 4))
    offset = offset + 4
    local msg_type = tvbuf(offset, 4):le_uint()
    subtree:add_le(header_fields.message_type, tvbuf(offset, 4))

    offset = offset + 4
    subtree:add_le(header_fields.tag, tvbuf(offset, 4))
    offset = offset + 4

    payload_length = msg_length - offset

    dprint2("payload_length", payload_length)

    -- if (msg_type == MESSAGE_PLIST) then
    -- message_plist.fields = {plist_field}
    -- local extendtree = subtree:add(message_plist, tvbuf(offset, msg_length-offset):tvb(),"message")
    -- extendtree:add(header_fields.payload, tvbuf(offset, msg_length-offset))
    -- https://stackoverflow.com/questions/46149825/wireshark-display-filters-vs-nested-dissectors

    -- local bplist_dissector = Dissector.get("bplist")
    -- local xml_dissector = Dissector.get("xml")
    -- xml_dissector(tvbuf(offset, msg_length-offset):tvb(), pktinfo, subtree)

    -- local extendtree = subtree:add(plist_dissector,
    --                                tvbuf(offset, msg_length - offset):tvb(),
    --                                "message")
    plist_dissector(tvbuf(offset, payload_length):tvb(), pktinfo, subtree)

    -- xml_dissector.dissector(tvbuf(offset, msg_length-offset):tvb(), pktinfo, subtree)
    -- end
    return msg_length
end

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    {1, "Disabled", debug_level.DISABLED}, {2, "Level 1", debug_level.LEVEL_1},
    {3, "Level 2", debug_level.LEVEL_2}
}

----------------------------------------
-- register our preferences
usbmux_protocol.prefs.port = Pref.uint("Dissector port", default_settings.port,
                                       "tcp port")

usbmux_protocol.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level",
                                        debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function usbmux_protocol.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = usbmux_protocol.prefs.debug
    resetDebugLevel()

    if usbmux_protocol.prefs.port ~= default_settings.port then
        default_settings.port = usbmux_protocol.prefs.port
        -- -- have to reload the capture file for this type of change
        -- reload()
    end

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(default_settings.port, usbmux_protocol)
-- tcp_port:add(default_settings.port, tls_dissector)

-- local function heuristic_checker(buffer, pinfo, tree)
--     -- guard for length
--     length = buffer:len()
--     if length < math.min(USBMUX_MSG_HDR_LEN, TLS_MSG_HDR_LEN) then return false end

--     local potential_proto_flag = buffer(0, 1):uint()
--     if potential_proto_flag ~= 0xd3 then return false end

--     local potential_msg_id = buffer(1, 2):uint()

--     if get_message_name(potential_msg_id) ~= "Unknown" then
--         scp_protocol.dissector(buffer, pinfo, tree)
--         return true
--     else
--         return false
--     end
-- end

-- -- register as heuristic dissector for both TCP and TLS 
-- usbmux_protocol:register_heuristic("tcp", heuristic_checker)
-- usbmux_protocol:register_heuristic("tls", heuristic_checker)

local tls_tcp_port = DissectorTable.get("tls.port")
tls_tcp_port:add(default_settings.port, usbmux_protocol)
