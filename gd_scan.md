python  gd_sacn.py  " http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo"

 对目标url扫描cve

python -f xxx.txt 批量扫cve

python -u  "http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo"  -fuzz "post=aa&post2=bb"

对post包的所有参数进行fuzz扫描cve

python  -u  "http://www.waitalone.cn/a/b/c/index.php?id=aa&abc=456&xxx=ooo" -data "post=aa&post2=bb" -p post

对特定post包的参数post进行fuzz扫描cve

后续加入更多cve检测。。。

shell 功能未实现