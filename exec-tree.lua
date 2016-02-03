--[[
Copyright (c) 2015 Ilya Rusalowski

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

This chisel is dedicated to littlemouse. So little and so inspiring )
]]

description = "Shows timeline of processes execution and opened files (optional)"
short_description = "Child processes execution tree"
category = "misc"

--[[
This is just an example. Script was written for very specific debugging
purposes, please, use plain sysdig or strace if you need.

~# # track mysql startup, ignore opened files
~# sysdig -c exec-tree.lua 'mysql false' > out &
~# service mysql start && kill %1
~# grep mysql out | uniq
-- execve /bin/sh /usr/sbin/service.mysql.start.
--- execve /bin/bash /etc/init.d/mysql.start.
------ execve dirname /etc/init.d/mysql.
---- execve basename /etc/init.d/mysql.
----- execve /usr/sbin/mysqld --print-defaults.
...
]]

args = 
{
    {
        name = "proc_substr", 
        description = "Filter for processes to track (children will be tracked automatically)", 
        argtype = "string",
        optional = true
    },
    {
        name = "track_open_files", 
        description = "Track open() syscall",
        argtype = "boolean",
        optional = true
    },
}

require "common"

root_ptree = {}
ptree_level = {}
files_uniq_level = {}
res_data = {}
max_ptree_id = 0
proc_substr = nil
track_open_files = false

function on_set_arg(name, val)
    if name == "proc_substr" then
        proc_substr = val
        return true
    elseif name == "track_open_files" then
        track_open_files = ((type(val) == 'boolean' and val == true) or (type(val) == 'string' and val == 'true'))
        return true
    end
    return false
end

function on_init()
    f_evt_type = chisel.request_field("evt.type")
    f_evt_args = chisel.request_field("evt.args")
    f_proc_pid = chisel.request_field("proc.pid")
    f_proc_ppid = chisel.request_field("proc.ppid")
    f_proc_cmdline = chisel.request_field("proc.cmdline")
    f_fd_name = chisel.request_field("fd.name")
    f_evt_rawtime_s = chisel.request_field("evt.rawtime.s")
    f_evt_num = chisel.request_field("evt.num")

    -- set global filter
    if string.len(sysdig.get_filter()) > 0 then
        chisel.set_filter("(evt.type=execve or evt.type=clone or evt.type=open) and " .. sysdig.get_filter())
    else
        chisel.set_filter("(evt.type=execve or evt.type=clone or evt.type=open)")
    end

    return true
end

function on_event()
    local evt_type = evt.field(f_evt_type)
    local pid = evt.field(f_proc_pid)
    local ppid = evt.field(f_proc_ppid)
    local proc_cmdline = evt.field(f_proc_cmdline)
    local evt_rawtime_s = evt.field(f_evt_rawtime_s)
    local evt_num = evt.field(f_evt_num)

    local new_ptree = true
    for ptree_id, ptree in ipairs(root_ptree) do
        if (root_ptree[ptree_id]['child_pids'] and
                (root_ptree[ptree_id]['child_pids'][ppid] or root_ptree[ptree_id]['child_pids'][pid])) then
            new_ptree = false
            break
        end
    end

    if new_ptree == true then
        local evt_args = evt.field(f_evt_args)
        if proc_substr ~= nil and ((proc_cmdline ~= nil and string.find(proc_cmdline, proc_substr) == nil) or
                (evt_args ~= nil and string.find(evt_args, proc_substr) == nil)) then
            return true
        end

        root_ptree[max_ptree_id] = {}
        root_ptree[max_ptree_id]['root_pid'] = pid
        root_ptree[max_ptree_id]['child_pids'] = {}
        ptree_level[pid] = 1
    
        ptree_id = max_ptree_id
        max_ptree_id = max_ptree_id + 1
    end
    if evt_type == 'clone' then
        root_ptree[ptree_id]['child_pids'][pid] = true
        if ptree_level[ppid] == nil then ptree_level[ppid] = 1 end
        ptree_level[pid] = ptree_level[ppid] + 1
    end

    if evt_type == 'execve' then
        -- res=0 exe=stat args=-c.%F:%U./var/lock/apache2. tid=6104(stat) pid=6104(stat) ptid=6103(apache2ctl)
        local evt_args_list = split(evt.field(f_evt_args), " ")
        if evt_args_list[2] ~= nil and evt_args_list[3] ~= nil then
            local exe_name = split(evt_args_list[2], "=")[2]
            local exe_args = split(evt_args_list[3], "=")[2]

            --print(ptree_id, evt_num, ptree_level[pid], evt_type, exe_name, exe_args) --, 'raw_data:', evt.field(f_evt_args))
            store_res_data(ptree_id, ptree_level[pid], evt_type, exe_name .. " " .. exe_args)
        end
    elseif track_open_files == true and evt_type == 'open' and evt.field(f_fd_name) ~= nil then
        local fd_name = evt.field(f_fd_name)
        if files_uniq_level[fd_name] ~= nil and files_uniq_level[fd_name][ptree_level[pid]] == true then
            return true
        else
            if files_uniq_level[fd_name] == nil then files_uniq_level[fd_name] = {} end
            files_uniq_level[fd_name][ptree_level[pid]] = true

            --print(ptree_id, evt_num, ptree_level[pid], evt_type, evt.field(f_fd_name))
            store_res_data(ptree_id, ptree_level[pid], evt_type, evt.field(f_fd_name))
        end
    end

    return true
end

function on_capture_end()
    print("process trees")
    for ptree_id, events in pairs(res_data) do
        print("process tree: ", ptree_id, "events:", #events)
        for evt_num, data in ipairs(events) do
            local ptree_level_str = ptree_level_to_str(data["ptree_level"])
            print(string.format("%s %s %s", ptree_level_str, data["type"], data["args"]))
        end
    end
    return true
end

function store_res_data(ptree_id, ptree_level, evt_type, evt_args)
    if res_data[ptree_id] == nil then res_data[ptree_id] = {} end

    local data = {}
    data["ptree_level"] = ptree_level
    data["type"] = evt_type
    data["args"] = evt_args
    table.insert(res_data[ptree_id], data)
end

function ptree_level_to_str(ptree_level)
    local level_str = ""
    for i=0,ptree_level do
        level_str = level_str .. "-" 
    end
    return level_str
end

