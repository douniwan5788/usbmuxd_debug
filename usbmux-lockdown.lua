local plist_dissector = Dissector.get("plist")

lockdown_protocol = Proto("lockdown", "Apple USBMUX lockdown service Protocol")
local LOCKDOWN_MSG_HDR_LEN = 4

local header_fields = {
    payload_length = ProtoField.uint32("lockdown.payload_length",
                                       "payload_length", base.DEC),
    payload = ProtoField.string("lockdown.payload", "payload")
}
lockdown_protocol.fields = header_fields

checkLength = function(tvbuf, offset)
    local remainlen = tvbuf:len() - offset

    if remainlen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        print("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if remainlen < LOCKDOWN_MSG_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        print("Need more bytes to figure out length field")
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this messsage

    -- in lockdownd frame, msgLen is big-endian and does not include msgLen itself(4 bytes)
    msgLen = tvbuf(offset, 4):uint() + 4

    if msgLen > remainlen then
        -- we need more bytes to get the whole message
        print("Need more bytes to desegment full")
        return -(msgLen - remainlen)
    end

    return msgLen
end

function lockdown_protocol.dissector(tvbuf, pktinfo, root_tree)
    local offset = 0
    local result = checkLength(tvbuf, offset)
    if result <= 0 then return result end

    -- in lockdownd frame, msgLen is big-endian and does not include msgLen itself(4 bytes)
    pktinfo.cols.protocol:append('/' .. lockdown_protocol.name)
    local subtree = root_tree:add(lockdown_protocol, tvbuf(),
                                  "USBMUX lockdown Protocol Data")
    msg_length = result
    payload_length = msg_length - 4
    subtree:add(header_fields.payload_length, tvbuf(offset, 4))
    offset = offset + 4
    -- subtree:add(header_fields.payload, tvbuf(offset, payload_length))
    plist_dissector(tvbuf(offset, payload_length):tvb(), pktinfo, subtree)
end

-- function lockdown_protocol.init()
--     local usbmux_subproto = DissectorTable.get("usbmux.subproto")
--     usbmux_subproto:add(0, lockdown_protocol)
-- end

-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(0, lockdown_protocol)
