local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"


description = [[
    A middleware sensitive directory scan script
]]

author = "Rvn0xsy@gmail.com"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default"}
blog = "https://payloads.online"
-- Precision mode
-- portrule = shortport.port_or_service( {80, 443, 8080, 7001}, {"http", "https"}, "tcp", "open")

portrule = shortport.service({"http","https"},"tcp","open")

action = function(host, port)
    out = stdnse.output_table()
    local status, result , body = http.identify_404(host,port)
    local all = nil
    request_paths = {
    "/phpinfo.php",
    "/manager/html",
    "/_async/AsyncResponseService",
    "/console/login/LoginForm.jsp",
    "/phpmyadmin/",
    "/web-console",
    "/jmx-console",
    "/host-manager",
    "/status",
    "/logs/access_log",
    "/jonasAdmin/",
    "/ibm/console/logon.jsp"
}

    for key,value in ipairs(request_paths)
    do
        all = http.pipeline_add(value,nil,all,'GET') 
    end

    local results = http.pipeline_go(host, port, all)

    for num,res in ipairs(results)do
        if(res.status ~= result)then
           out[num] =  request_paths[num]
        end
    end

    return out
end