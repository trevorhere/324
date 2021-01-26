
``` set SHELL=/bin/bash #in tsch```
``` SHELL=/bin/bash #in bash```

```env``` get enviroment variables

```more  getenv1.c```

```getenv``` exists in the std library to get env

Uppercase for globabl env

```BYU=fall```

```./get3 SHELL``` git@github.com:trevorhere/CS324.git

```export BYU2=fall``` git@github.com:trevorhere/CS324.git``` sets env variable and exports to ?

```CS324=today ./get3 CS324 => CS324: today```

#### I/O Redirection

file descriptors:
```stdin:0, stdout:1 stderr:2```

man: ```man ls, man cat ```
```more  /etc/password```
`
```less  /etc/password```: output to terminal

```less /etc/password > tmpfile ```
```less tmpfile ``` prints file


```fprintf```
```./std 2> errfile``` puts stderr into errfile

*interesting, you can control output based on output type..v cool```


```./std > tmpfile 2>&1``` ampersand directs toward the first file

```./std >tmpfile``` doesnt output stder to tmpfile

#### Pipes

```man grep ```

```grep stderr std.c``` prints lines w/ std err

``` more std.c | grep stderr``` gets file,pipes to grep and prints line w/ stderr

```more etc/passwd```