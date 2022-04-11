-- bplist.lua
--
-- Wireshark dissector for Apple bplist protocol used by Safari Remote Debugging
--
-- Copyright (C) 2013 Andy Davies (hello@andydavies.me)
--
-- Example usage
--  tshark -X lua_script:bplist.lua -i lo0 -f "tcp port 27753" -O bplist -V
--
-- Heavily influenced by
--   http://delog.wordpress.com/2010/09/27/create-a-wireshark-dissector-in-lua/
--   http://opensource.apple.com/source/CF/CF-550/CFBinaryPList.c
--   https://github.com/nearinfinity/node-bplist-parser
--   http://code.google.com/p/plist/
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k, v in pairs(o) do
            if type(k) ~= 'number' then k = '"' .. k .. '"' end
            s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

do
    p_bplist = Proto("bplist", "Apple Binary Plist")

    p_bplist.fields = {f_data}

    local offsetTable = {}
    local offsetSize = 0
    local objectRefSize = 0
    local numObjects = 0
    local topObject = 0
    local offsetTableOffset = 0

    -- dissector function
    function p_bplist.dissector(buffer, pkt, root)

        -- Check buffer length, otheriwse quit
        if buffer:len() < 6 then
            local subtree = root:add(p_bplist, buffer(0))
            subtree:add(f_data, buffer(0):string())
            print(buffer)
            return
        end

        -- Check for magic number, otherwise quit
        local magic_number = buffer(0, 6):string()
        if magic_number ~= "bplist" then
            print(buffer)
            return
        end

        pkt.cols.protocol:append('/' .. p_bplist.name)

        -- add protocol fields to subtree
        -- trailer is last 32 bytes of data
        local trailer = buffer:len() - 32

        offsetSize = buffer(trailer + 6, 1):uint()
        objectRefSize = buffer(trailer + 7, 1):uint()
        numObjects = tonumber(tostring(buffer(trailer + 8, 8):uint64()))
        topObject = tonumber(tostring(buffer(trailer + 16, 8):uint64()))
        offsetTableOffset = tonumber(tostring(buffer(trailer + 24, 8):uint64()))
        print(offsetSize, objectRefSize, numObjects, topObject,
              offsetTableOffset)
        for i = 0, numObjects, 1 do
            local offsetBytes = buffer(offsetTableOffset + i * offsetSize,
                                       offsetSize):uint();
            offsetTable[i] = offsetBytes;
        end

        local t, range = unpack(parseObject(buffer, topObject))

        print("start build_tree t:", t, "range:", range)
        -- create subtree for myproto
        local subtree = root:add(p_bplist, buffer())
        build_tree(t, range, subtree)

        --    print(string.rep ("=", 60) .. "\n")
        --    table_print(t, 4)
        --    print("\n" .. string.rep ("=", 60) .. "\n")

    end

    function build_tree(obj, range, parent)
        if type(obj) == "table" then
            for key, v in pairs(obj) do
                print("build_tree key", key)

                value, val_range = unpack(v)
                print("build_tree value", value, val_range)

                if type(value) == "table" then
                    local node = parent:add(val_range, tostring(key))
                    build_tree(value, val_range, node)
                else
                    parent:add(val_range, tostring(key), tostring(value))
                end
            end
        else
            parent:add(range, tostring(obj)) -- Is this right, will it ever be reached?
        end
    end

    function table_print(tt, indent, done)
        done = done or {}
        indent = indent or 0
        if type(tt) == "table" then
            for key, value in pairs(tt) do
                if type(value) == "table" then
                    print(string.format("%s: ", tostring(key)));
                    print("{");
                    table_print(value, indent + 7, done)
                    print("}");
                else
                    print(
                        string.format("%s: %s", tostring(key), tostring(value)))
                end
            end
        else
            print("tt:" .. tt)
        end
    end

    function parseObject(buffer, tableOffset)
        local startPos = offsetTable[tableOffset];
        print("parseObject", tableOffset, startPos)

        -- each table entry starts with single byte header, indicating type and extra info
        local type = buffer(startPos, 1):uint()
        local objType = bit.rshift(type, 4)
        local objInfo = bit.band(type, 0x0F)

        -- null
        if objType == 0x0 and objInfo == 0x0 then -- null
            return {nil, buffer(startPos, 1)}

            -- false          
        elseif objType == 0x0 and objInfo == 0x8 then -- false
            return {false, buffer(startPos, 1)}

            -- true          
        elseif objType == 0x0 and objInfo == 0x9 then -- true
            return {true, buffer(startPos, 1)}

            -- filler          
        elseif objType == 0x0 and objInfo == 0xF then -- filler byte
            return {nil, buffer(startPos, 1)}

            -- integer
            -- UID
        elseif objType == 0x1 or objType == 0x8 then
            local length = 2 ^ objInfo
            return {
                buffer(startPos + 1, length):uint(),
                buffer(startPos, 1 + length)
            }

            -- real        
        elseif objType == 0x2 then -- real
            local length = 2 ^ objInfo
            return {
                buffer(startPos + 1, length):float(),
                buffer(startPos, 1 + length)
            }

            -- date        
        elseif objType == 0x3 then -- date
            if (objInfo ~= 0x3) then
                print("Error: Unknown date type :", objInfo)
            end
            return {buffer(startPos + 1, 8):float(), buffer(startPos, 1 + 8)} -- TODO: Format correctly

            -- data        
        elseif objType == 0x4 then -- data
            local length = objInfo
            local dataOffset = 1
            if (objInfo == 0xF) then -- 1111
                local int_type = buffer(startPos + 1, 1):int()
                local intType = bit.band(int_type, 0xF0) / 0x10;
                if intType ~= 0x1 then
                    print("Error : 0x4 Unexpected length - int-type", intType)
                end
                intInfo = bit.band(int_type, 0x0F)
                intLength = 2 ^ intInfo
                dataOffset = 2 + intLength
                length = buffer(startPos + 2, intLength):int()
            end

            -- how to determine which one to use?        
            --        print(buffer(startPos + dataOffset, length):bytes())
            -- 0x7B is {
            --      print("===== data ===== ", buffer(startPos + dataOffset, length):string())
            return {
                buffer(startPos + dataOffset, length):string(),
                buffer(startPos, dataOffset + length)
            }

            -- ASCII String        
        elseif objType == 0x5 then -- ASCII
            local length = objInfo
            local strOffset = 1
            if (objInfo == 0xF) then -- 1111
                local int_type = buffer(startPos + 1, 1):int()
                local intType = bit.band(int_type, 0xF0) / 0x10;
                if intType ~= 0x1 then
                    print("Error : 0x5 Unexpected length - int-type", intType)
                end
                intInfo = bit.band(int_type, 0x0F)
                intLength = 2 ^ intInfo
                strOffset = 2 + intLength
                length = buffer(startPos + 2, intLength):int()
            end
            return {
                buffer(startPos + strOffset, length):string(),
                buffer(startPos, strOffset + length)
            }

            -- UTF16 String        
        elseif objType == 0x6 then -- UTF-16
            local length = objInfo
            local strOffset = 1
            if (objInfo == 0xF) then -- 1111
                local int_type = buffer(startPos + 1, 1):int()
                local intType = bit.band(int_type, 0xF0) / 0x10;
                if intType ~= 0x1 then
                    print("Error : 0x6 Unexpected length - int-type", intType)
                end
                intInfo = bit.band(int_type, 0x0F)
                intLength = 2 ^ intInfo
                strOffset = 2 + intLength
                length = buffer(startPos + 2, intLength):int()
            end
            length = length * 2
            --      print("===== UTF16 String =====")
            --      print("length: ", length)
            --      print(buffer(startPos + strOffset, length):len())
            --      print(buffer(startPos + strOffset, length):ustring())
            --      return "UTF16String"

            return {
                buffer(startPos + strOffset, length):ustring(),
                buffer(startPos, strOffset + length)
            }

            -- Array        
        elseif objType == 0xA then
            local length = objInfo
            local arrayOffset = 1
            if (objInfo == 0xF) then -- 1111
                local int_type = buffer(startPos + 1, 1):int()
                local intType = bit.band(int_type, 0xF0) / 0x10;
                if intType ~= 0x1 then
                    print("Error : 0xA Unexpected length - int-type", intType)
                end
                intInfo = bit.band(int_type, 0x0F)
                intLength = 2 ^ intInfo
                arrayOffset = 2 + intLength
                length = buffer(startPos + 2, intLength):int()
            end
            local array = {}
            for i = 0, length - 1, 1 do
                objRef = buffer(startPos + arrayOffset + i * objectRefSize,
                                objectRefSize):uint()
                array[i] = parseObject(buffer, objRef)
            end
            return {array, buffer(startPos, length)} -- todo

            -- Set
        elseif objType == 0xC then
            --      print("===== Set =====")  
            return "TODO: Add in Set!!!" -- TODO

            -- Dictionary        
        elseif objType == 0xD then
            local length = objInfo
            local dictOffset = 1
            if (objInfo == 0xF) then -- 1111
                local int_type = buffer(startPos + 1, 1):int()
                local intType = bit.band(int_type, 0xF0) / 0x10;
                if intType ~= 0x1 then
                    print("Error : 0xD Unexpected length - int-type", intType)
                end
                intInfo = bit.band(int_type, 0x0F)
                intLength = 2 ^ intInfo
                dictOffset = 2 + intLength
                length = buffer(startPos + 2, intLength):int()
            end
            local dict = {}
            for i = 0, length - 1, 1 do
                local keyRef = buffer((startPos + dictOffset) +
                                          (i * objectRefSize), objectRefSize):uint()
                local valRef = buffer((startPos + dictOffset + length) +
                                          (i * objectRefSize), objectRefSize):uint()
                local key = parseObject(buffer, keyRef);
                key, _ = unpack(key)
                local val = parseObject(buffer, valRef);
                print("key: ", key)
                print("val: ", unpack(val))
                dict[key] = val
            end
            return {dict, buffer(startPos, length)} -- TODO
        end

        -- Unkown type return error message
        return "Error : Unknown object type - " .. objType

    end

    -- Initialization routine
    function p_bplist.init() end

    -- register chained dissector on port 27753 (is it always this port?)
    tcp_dissector_table = DissectorTable.get("tcp.port")
    tcp_dissector_table:add(27753, p_bplist)

end
