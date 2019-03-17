unsigned __int64 __fastcall
cmd_auth(__int64 cmd, unsigned __int64 buf_size)
{
  void *local_buf; // rsp
  __int64 _local_buf; // [rsp+0h] [rbp-70h]
  unsigned __int64 v5; // [rsp+8h] [rbp-68h]
  unsigned __int8 msg_len; // [rsp+15h] [rbp-5Bh]
  unsigned __int8 size; // [rsp+16h] [rbp-5Ah]
  char first_byte_plus_one; // [rsp+17h] [rbp-59h]
  unsigned __int64 v9; // [rsp+18h] [rbp-58h]
  unsigned __int8 *__local_buf; // [rsp+20h] [rbp-50h]
  unsigned __int8 *___local_buf; // [rsp+28h] [rbp-48h]
  void *uid; // [rsp+30h] [rbp-40h]
  __int64 user; // [rsp+38h] [rbp-38h]
  __int64 resp_code; // [rsp+40h] [rbp-30h]
  __int64 v15; // [rsp+48h] [rbp-28h]
  unsigned __int64 canary; // [rsp+58h] [rbp-18h]

  _local_buf = cmd;
  v5 = buf_size;
  canary = __readfsqword(0x28u);
  v9 = buf_size - 1;
  local_buf = alloca(16 * ((buf_size + 15) / 16));
  __local_buf = &_local_buf;
  readn(&_local_buf, buf_size);
  ___local_buf = __local_buf;
  msg_len = *__local_buf;
  size = 0x80u;
  first_byte_plus_one = msg_len + 1;
  if ( (msg_len + 1) <= 0x80u )
  {
    uid = allocator_alloc(size);
    user = allocator_alloc(0x118LL);
    *user = 1;
    *(user + 8) = uid;
    *(user + 16) = allocator_dealloc;
    memcpy(uid, ___local_buf + 1, msg_len);
    *(uid + msg_len) = 0;
    *(root_ctx + 5) = user;
    resp_code = 200LL;
    v15 = 0LL;
    write_header(200LL, 0LL);
  }
  else
  {
    firfirfir("auth message too big");
  }
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64 __fastcall
cmd_head(__int64 cmd, unsigned __int64 buf_size)
{
  void *v2; // rsp
  __int64 _cmd; // [rsp+0h] [rbp-1020h]
  __int64 _buf_size; // [rsp+8h] [rbp-1018h]
  __int64 v6; // [rsp+18h] [rbp-1008h]
  void *idx; // [rsp+20h] [rbp-1000h]
  FILE *fp; // [rsp+28h] [rbp-FF8h]
  __int64 v9; // [rsp+30h] [rbp-FF0h]
  __int64 v10; // [rsp+38h] [rbp-FE8h]
  char filename; // [rsp+40h] [rbp-FE0h]
  unsigned __int64 canary; // [rsp+FE8h] [rbp-38h]

  _cmd = cmd;
  _buf_size = buf_size;
  canary = __readfsqword(0x28u);
  check_auth();
  check_auth();
  v6 = _buf_size;
  v2 = alloca(16 * ((_buf_size + 16) / 16uLL));
  idx = &_cmd;
  bzero(&_cmd, _buf_size + 1);
  readn(idx, _buf_size);
  check_path_part(idx);
  snprintf(&filename, 0xFA0uLL, "data/%s_%s", *(*(root_ctx + 5) + 8LL), idx);
  fp = fopen(&filename, "rb");
  if ( fp )
  {
    fclose(fp);
    v9 = 200LL;
    v10 = 0LL;
    write_header(200LL, 0LL);
  }
  else
  {
    v9 = 404LL;
    v10 = 0LL;
    write_header(404LL, 0LL);
  }
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64 __fastcall
cmd_put(__int64 cmd, unsigned __int64 buf_size)
{
  void *local_buf; // rsp
  void *v3; // rsp
  void *v4; // rsp
  __int64 v6; // [rsp+0h] [rbp-1090h]
  __int64 v7; // [rsp+8h] [rbp-1088h]
  __int64 v8; // [rsp+10h] [rbp-1080h]
  __int64 v9; // [rsp+18h] [rbp-1078h]
  unsigned __int64 ___buf_size; // [rsp+20h] [rbp-1070h]
  __int64 v11; // [rsp+28h] [rbp-1068h]
  unsigned __int64 __buf_size; // [rsp+30h] [rbp-1060h]
  __int64 v13; // [rsp+38h] [rbp-1058h]
  __int64 _cmd; // [rsp+40h] [rbp-1050h]
  unsigned __int64 _buf_size; // [rsp+48h] [rbp-1048h]
  size_t lens; // [rsp+58h] [rbp-1038h]
  __int64 *__local_buf; // [rsp+60h] [rbp-1030h]
  unsigned __int64 _buf_size_minus_one; // [rsp+68h] [rbp-1028h]
  __int64 *___local_buf; // [rsp+70h] [rbp-1020h]
  __int64 v20; // [rsp+78h] [rbp-1018h]
  void *idx; // [rsp+80h] [rbp-1010h]
  __int64 v22; // [rsp+88h] [rbp-1008h]
  void *data; // [rsp+90h] [rbp-1000h]
  FILE *fp; // [rsp+98h] [rbp-FF8h]
  __int64 v25; // [rsp+A0h] [rbp-FF0h]
  __int64 v26; // [rsp+A8h] [rbp-FE8h]
  char filename; // [rsp+B0h] [rbp-FE0h]
  unsigned __int64 canary; // [rsp+1058h] [rbp-38h]

  _cmd = cmd;
  _buf_size = buf_size;
  canary = __readfsqword(0x28u);
  check_auth();
  _buf_size_minus_one = _buf_size - 1;
  __buf_size = _buf_size;
  v13 = 0LL;
  ___buf_size = _buf_size;
  v11 = 0LL;
  local_buf = alloca(16 * ((_buf_size + 15) / 16));
  __local_buf = &v6;
  if ( _buf_size <= 1 )
    firfirfir("too small");
  readn(__local_buf, _buf_size);
  ___local_buf = __local_buf;
  LODWORD(lens) = *__local_buf;
  HIDWORD(lens) = *(__local_buf + 1);
  if ( (lens + HIDWORD(lens) + 2) > _buf_size )
    firfirfir("too big");
  v20 = (lens + 1) - 1LL;
  v8 = (lens + 1);
  v9 = 0LL;
  v6 = (lens + 1);
  v7 = 0LL;
  v3 = alloca(16 * ((v8 + 15) / 0x10uLL));
  idx = &v6;
  v22 = (HIDWORD(lens) + 1) - 1LL;
  v4 = alloca(16 * (((HIDWORD(lens) + 1) + 15) / 0x10));
  data = &v6;
  memcpy(&v6, ___local_buf + 2, lens);
  *(idx + lens) = 0;
  memcpy(data, ___local_buf + lens + 2, HIDWORD(lens));
  *(data + HIDWORD(lens)) = 0;
  check_path_part(idx);
  snprintf(&filename, 0xFA0uLL, "data/%s_%s", *(*(root_ctx + 5) + 8LL), idx);
  fp = fopen(&filename, "wb");
  if ( !fp )
    __assert_fail("f", "/vagrant/spbctf/fargate-training/kv8/main.c", 0x65u, "cmd_put");
  fwrite(data, 1uLL, HIDWORD(lens), fp);
  fclose(fp);
  v25 = 200LL;
  v26 = 0LL;
  write_header(200LL, 0LL);
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64 __fastcall
cmd_get(__int64 cmd, unsigned __int64 buf_size)
{
  void *v2; // rsp
  void *v3; // rsp
  size_t _data; // [rsp+0h] [rbp-1050h]
  __int64 v6; // [rsp+8h] [rbp-1048h]
  __int64 v7; // [rsp+10h] [rbp-1040h]
  __int64 v8; // [rsp+18h] [rbp-1038h]
  __int64 v9; // [rsp+20h] [rbp-1030h]
  __int64 v10; // [rsp+28h] [rbp-1028h]
  __int64 _cmd; // [rsp+30h] [rbp-1020h]
  __int64 _buf_size; // [rsp+38h] [rbp-1018h]
  __int64 v13; // [rsp+40h] [rbp-1010h]
  void *idx; // [rsp+48h] [rbp-1008h]
  FILE *fp; // [rsp+50h] [rbp-1000h]
  size_t data_len; // [rsp+58h] [rbp-FF8h]
  size_t v17; // [rsp+60h] [rbp-FF0h]
  void *data; // [rsp+68h] [rbp-FE8h]
  __int64 v19; // [rsp+70h] [rbp-FE0h]
  unsigned __int64 _data_len; // [rsp+78h] [rbp-FD8h]
  char filename; // [rsp+80h] [rbp-FD0h]
  unsigned __int64 canary; // [rsp+1028h] [rbp-28h]

  _cmd = cmd;
  _buf_size = buf_size;
  canary = __readfsqword(0x28u);
  check_auth();
  v13 = _buf_size;
  v9 = _buf_size + 1;
  v10 = 0LL;
  v7 = _buf_size + 1;
  v8 = 0LL;
  v2 = alloca(16 * ((_buf_size + 16) / 16uLL));
  idx = &_data;
  bzero(&_data, _buf_size + 1);
  readn(idx, _buf_size);
  check_path_part(idx);
  snprintf(&filename, 0xFA0uLL, "data/%s_%s", *(*(root_ctx + 5) + 8LL), idx);
  fp = fopen(&filename, "rb");
  if ( fp )
  {
    fseek(fp, 0LL, 2);
    data_len = ftell(fp);
    fseek(fp, 0LL, 0);
    v17 = data_len - 1;
    _data = data_len;
    v6 = 0LL;
    v3 = alloca(16 * ((data_len + 15) / 0x10));
    data = &_data;
    fread(&_data, 1uLL, data_len, fp);
    fclose(fp);
    v19 = 200LL;
    _data_len = data_len;
    write_header(200LL, data_len);
    writen(data, _data_len);
  }
  else
  {
    v19 = 404LL;
    _data_len = 0LL;
    write_header(404LL, 0LL);
  }
  return __readfsqword(0x28u) ^ canary;
}

__int64 __fastcall
cmd_quit(__int64 cmd, __int64 buf_size)
{
  __int64 user; // rax
  __int64 (__fastcall *dealloc)(_QWORD); // ST18_8
  size_t goodbye_len; // [rsp+28h] [rbp-8h]

  if ( buf_size )
    __assert_fail("header.l == 0", "/vagrant/spbctf/fargate-training/kv8/main.c", 0x93u, "cmd_quit");
  goodbye_len = strlen("goodby");
  write_header(200LL, goodbye_len);
  writen("goodby", goodbye_len);
  user = *(root_ctx + 5);
  if ( user )
  {
    dealloc = *(*(root_ctx + 5) + 16LL);
    (dealloc)(*(*(root_ctx + 5) + 8LL), goodbye_len);
    user = dealloc(*(root_ctx + 5));
  }
  return user;
}

unsigned __int64 __fastcall
ping(__int64 cmd, unsigned __int64 buf_size)
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

char *
init()
{
  char *_root_ctx; // rax
  char *result; // rax
  const char *debug; // [rsp+8h] [rbp-8h]

  allocator_alloc = &malloc;
  allocator_dealloc = &free;
  root_ctx = malloc(0x40uLL);
  bzero(root_ctx, 0x40uLL);
  _root_ctx = root_ctx;
  *root_ctx = 'srev 8vk';
  *(_root_ctx + 1) = '2424 noi';
  _root_ctx[16] = 0;
  *(root_ctx + 8) = 4242;
  debug = getenv("DEBUG");
  if ( debug && !strcmp("true", debug) )
    *(root_ctx + 6) = report_and_exit;
  else
    *(root_ctx + 6) = &exit;
  result = root_ctx;
  *(root_ctx + 7) = root_ctx;
  return result;
}

void
timeout()
{
  firfirfir("timeout");
}

int __cdecl
main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  signed int i; // [rsp+Ch] [rbp-14h]
  unsigned __int64 cmd; // [rsp+10h] [rbp-10h]
  __int64 buf_size; // [rsp+18h] [rbp-8h]

  init();
  for ( i = 0; i <= 5; ++i )
  {
    signal(14, timeout);
    alarm(3u);
    cmd = read_header();
    buf_size = v3;
    if ( cmd > 5 )
      firfirfir("wrong command");
    (*(&handlers + cmd))(cmd, buf_size);
  }
  return 0;
}

__int64 __fastcall
firfirfir(const char *a1)
{
  perror(a1);
  return (*(root_ctx + 6))(0LL);
}

unsigned __int64 __fastcall
writen(char *msg_buf, unsigned __int64 n)
{
  unsigned __int64 result; // rax
  unsigned __int64 bytes_written; // [rsp+18h] [rbp-18h]
  char *buf; // [rsp+20h] [rbp-10h]
  ssize_t len; // [rsp+28h] [rbp-8h]

  if ( !n )
    __assert_fail("n > 0", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x10u, "writen");
  if ( !msg_buf )
    __assert_fail("buf != NULL", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x11u, "writen");
  bytes_written = 0LL;
  buf = msg_buf;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        if ( bytes_written >= n )
          __assert_fail("bytes_written < n", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x15u, "writen");
        len = write(1, buf, n - bytes_written);
        if ( len >= 0 )
          break;
        firfirfir("reading error");
      }
      if ( len )
        break;
      firfirfir("reading eof");
    }
    buf += len;
    bytes_written += len;
    result = n;
  }
  while ( n != bytes_written );
  return result;
}

unsigned __int64 __fastcall
readn(char *res_buf, unsigned __int64 n)
{
  unsigned __int64 result; // rax
  unsigned __int64 bytes_read; // [rsp+18h] [rbp-18h]
  char *buf; // [rsp+20h] [rbp-10h]
  ssize_t len; // [rsp+28h] [rbp-8h]

  if ( !n )
    __assert_fail("n > 0", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x26u, "readn");
  if ( !res_buf )
    __assert_fail("buf != NULL", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x27u, "readn");
  bytes_read = 0LL;
  buf = res_buf;
  do
  {
    while ( 1 )
    {
      if ( bytes_read >= n )
        __assert_fail("bytes_read < n", "/vagrant/spbctf/fargate-training/kv8/proto.c", 0x2Bu, "readn");
      len = read(0, buf, n - bytes_read);
      if ( len >= 0 )
        break;
      firfirfir("reading error");
    }
    if ( !len )
      exit(0);
    buf += len;
    bytes_read += len;
    result = n;
  }
  while ( n != bytes_read );
  return result;
}

__int64
read_header()
{
  __int64 cmd; // [rsp+0h] [rbp-20h]
  unsigned __int64 msg_len; // [rsp+8h] [rbp-18h]
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  cmd = 0LL;
  msg_len = 0LL;
  readn(&cmd, 0x10uLL);
  if ( msg_len > 0x400 )
    firfirfir("msg too big");
  return cmd;
}

unsigned __int64 __fastcall
write_header(__int64 code, __int64 a2)
{
  __int64 buf; // [rsp+0h] [rbp-10h]
  __int64 v4; // [rsp+8h] [rbp-8h]

  buf = code;
  v4 = a2;
  return writen(&buf, 0x10uLL);
}

__int64
check_auth()
{
  if ( !*(root_ctx + 5) )
    firfirfir("not authorized");
  return check_path_part(*(*(root_ctx + 5) + 8LL));
}

__int64 __fastcall
check_path_part(const char *path)
{
  __int64 result; // rax
  char b; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]
  size_t path_len; // [rsp+18h] [rbp-8h]

  path_len = strlen(path);
  if ( !path_len || path_len > 0x80 )
    firfirfir("strange uid");
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( path_len <= i )
      break;
    b = path[i];
    if ( (b <= '`' || b > 'z') && (b <= '@' || b > 'Z') && (b <= '/' || b > '9') && b != '-' )
      firfirfir("bad uid");
  }
  return result;
}

int __fastcall
curl(const char *cmd)
{
  char *v1; // rax

  v1 = strstr(cmd, "curl");
  if ( v1 )
    LODWORD(v1) = system(cmd);
  return v1;
}

unsigned __int64 __fastcall
report_and_exit(unsigned int a1)
{
  char *host; // [rsp+18h] [rbp-FB8h]
  char buf; // [rsp+20h] [rbp-FB0h]
  unsigned __int64 canary; // [rsp+FC8h] [rbp-8h]

  canary = __readfsqword(0x28u);
  host = getenv("ANALYTICS_HOST");
  if ( host )
  {
    bzero(&buf, 0xFA0uLL);
    snprintf(&buf, 0xFA0uLL, &byte_27AA, host, a1);
    curl(&buf);
    exit(a1);
  }
  return __readfsqword(0x28u) ^ canary;
}