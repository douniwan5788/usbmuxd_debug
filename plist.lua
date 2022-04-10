plist_protocol = Proto("plist", "Apple Plist")

function plist_protocol.dissector(tvb, pinfo, tree)
    local xml_dissector = Dissector.get("xml")
    local bplist_dissector = Dissector.get("bplist")
    local plist_dissector = xml_dissector
    -- Check for magic number, otherwise quit
    local magic_number = tvb(0, 6):string()
    if magic_number == "bplist" then plist_dissector = bplist_dissector end
    -- pinfo.cols.protocol = "plist"
    plist_dissector(tvb, pinfo, tree)
end
