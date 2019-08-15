# gdscan
一个简单的cve漏洞扫描器


python gd_sacn.py“ http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo ”

对目标URL扫描CVE

python -f xxx.txt批量扫cve

python -u“ http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo ”-fuzz“post = aa＆post2 = bb”

对后包的所有参数进行模糊扫描CVE

python -u“ http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo ”-data“post = aa＆post2 = bb”-p post

对特定岗位包的参数后进行模糊扫描CVE

后续加入更多CVE检测...

shell功能未实现
