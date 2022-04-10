local plist_dissector = Dissector.get("plist")

dtxmessage_protocol = Proto("dtxmessage",
                            "Apple USBMUX dtxmessage service Protocol")

local DTXMESSAGE_MSG_HDR_LEN = 0x20
local DTXMESSAGE_PAYLOAD_HDR_LEN = 0x10

local header_fields = {
    magic = ProtoField.uint32("dtxmessage.magic", "magic", base.HEX),
    header_length = ProtoField.uint32("dtxmessage.header_length",
                                      "header_length", base.DEC),
    fragment_id = ProtoField.uint16("dtxmessage.fragment_id", "fragment_id",
                                    base.DEC),
    fragment_count = ProtoField.uint16("dtxmessage.fragment_count",
                                       "fragment_count", base.DEC),
    payload_length = ProtoField.uint32("dtxmessage.payload_length",
                                       "payload_length", base.DEC),
    message_id = ProtoField.uint32("dtxmessage.message_id", "message_id",
                                   base.DEC),
    conversation_index = ProtoField.uint32("dtxmessage.conversation_index",
                                           "conversation_index", base.DEC),
    channel = ProtoField.uint32("dtxmessage.channel", "channel", base.DEC),
    expects_reply = ProtoField.uint32("dtxmessage.expects_reply",
                                      "expects_reply", base.BOOL),

    flags = ProtoField.uint32("dtxmessage.flags", "flags", base.DEC),
    aux_length = ProtoField.uint32("dtxmessage.aux_length", "aux_length",
                                   base.DEC),
    total_length = ProtoField.uint64("dtxmessage.total_length", "total_length",
                                     base.DEC),

    payload = ProtoField.bytes("dtxmessage.payload", "payload")
}
dtxmessage_protocol.fields = header_fields

checkLength = function(tvbuf, offset)
    local remainlen = tvbuf:len() - offset

    if remainlen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        print("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if remainlen < DTXMESSAGE_MSG_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        print("Need more bytes to figure out length field")
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this messsage

    payload_length = tvbuf(offset + 12, 4):le_uint()
    msgLen = DTXMESSAGE_MSG_HDR_LEN + payload_length
    if msgLen > remainlen then
        -- we need more bytes to get the whole message
        print("Need more bytes to desegment full")
        return -(msgLen - remainlen)
    end

    return msgLen
end

function dtxmessage_protocol.dissector(tvbuf, pktinfo, root_tree)
    local offset = 0
    local result = checkLength(tvbuf, offset)
    if result <= 0 then return result end

    -- in dtxmessaged frame, msgLen is big-endian and does not include msgLen itself(4 bytes)
    pktinfo.cols.protocol:append('/' .. dtxmessage_protocol.name)
    local subtree = root_tree:add(dtxmessage_protocol, tvbuf(),
                                  "USBMUX DTXMessage Protocol Data")

    subtree:add_le(header_fields.magic, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.header_length, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.fragment_id, tvbuf(offset, 2))
    offset = offset + 2
    subtree:add_le(header_fields.fragment_count, tvbuf(offset, 2))
    offset = offset + 2
    subtree:add_le(header_fields.payload_length, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.message_id, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.conversation_index, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.channel, tvbuf(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.expects_reply, tvbuf(offset, 4))
    offset = offset + 4

    local bytes_consumed = 0
    while bytes_consumed < payload_length do
        local total_length = tvbuf(offset + 8, 8):le_uint64():tonumber()

        local payload_tree = subtree:add(tvbuf(offset,
                                               DTXMESSAGE_PAYLOAD_HDR_LEN +
                                                   total_length),
                                         "DTXMessage Payload")
        payload_tree:add_le(header_fields.flags, tvbuf(offset, 4))
        offset = offset + 4
        payload_tree:add_le(header_fields.aux_length, tvbuf(offset, 4))
        offset = offset + 4
        payload_tree:add_le(header_fields.total_length, tvbuf(offset, 8))
        offset = offset + 8
        payload_tree:add(header_fields.payload, tvbuf(offset, total_length))
        offset = offset + total_length

        bytes_consumed = bytes_consumed + DTXMESSAGE_PAYLOAD_HDR_LEN +
                             total_length
    end

    -- plist_dissector(tvbuf(offset, payload_length):tvb(), pktinfo, subtree)
end

-- function dtxmessage_protocol.init()
--     local usbmux_subproto = DissectorTable.get("usbmux.subproto")
--     usbmux_subproto:add(0, dtxmessage_protocol)
-- end

-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(0, dtxmessage_protocol)
