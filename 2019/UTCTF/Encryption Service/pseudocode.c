int
print_key(void)
{
  return puts("OTP Encryption");
}

int
print_xor(void)
{
  return puts("XOR Encryption");
}

const char *__fastcall
key_encrypt(__int64 msg, const char *skey)
{
  const char *result; // rax
  int i; // [rsp+18h] [rbp-18h]
  size_t skey_len; // [rsp+20h] [rbp-10h]
  size_t key_len; // [rsp+28h] [rbp-8h]

  skey_len = strlen(skey);
  key_len = strlen(key);
  for ( i = 0; i < skey_len; ++i )
    skey[i] ^= key[(i % key_len)];
  result = &skey[skey_len];
  skey[skey_len] = 0;
  return result;
}

const char *__fastcall
xor_encrypt(__int64 msg, const char *key)
{
  const char *result; // rax
  char byte; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]
  size_t key_len; // [rsp+18h] [rbp-8h]

  byte = user_id;
  key_len = strlen(key);
  for ( i = 0; i < key_len; ++i )
    key[i] = byte ^ *(i + msg);
  result = &key[key_len];
  key[key_len] = 0;
  return result;
}

unsigned __int64
edit_encrypted_message(void)
{
  int index; // [rsp+4h] [rbp-1Ch]
  __int128 msg; // [rsp+8h] [rbp-18h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Enter the index of the message that you wish to edit");
  __isoc99_scanf("%d%*c", &index);
  if ( index >= 0 && index <= 19 && information[index] )
  {
    msg = *information[index];
    puts("Enter the new message");
    fgets(msg, *(information[index] + 36), stdin);
    (*(information[index] + 16))(msg, *(&msg + 1));
  }
  else
  {
    puts("Invalid index");
  }
  return __readfsqword(0x28u) ^ v3;
}

int
print_menu(void)
{
  puts("Welcome to Encryption as a Service!\n What would you like to do?");
  puts("1. Encrypt message");
  puts("2. Remove Encrypted Message");
  puts("3. View Encrypted Message");
  puts("4. Edit Encrypted Message");
  puts("5. Exit");
  return putchar(62);
}

int
print_encryption_menu(void)
{
  puts("Choose an encryption option:");
  puts("1. OTP");
  puts("2. XOR");
  return putchar(62);
}

signed __int64
find_index(void)
{
  signed int i; // [rsp+0h] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    if ( !information[i] || *(information[i] + 32) )
      return i;
  }
  return 0xFFFFFFFFLL;
}

__int64
create_info(void)
{
  __int64 result; // rax
  int index; // [rsp+Ch] [rbp-4h]

  index = find_index();
  if ( index == -1 )
  {
    puts("You've reached the maximum number of messages that you can store.");
    result = 0LL;
  }
  else
  {
    if ( !information[index] )
      information[index] = malloc(0x28uLL);
    *(information[index] + 32) = 0;
    result = information[index];
  }
  return result;
}

int
view_messages(void)
{
  __int64 info; // rax
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    info = information[i];
    if ( info )
    {
      LODWORD(info) = *(information[i] + 32);
      if ( !info )
      {
        printf("Message #%d\n", i);
        (*(information[i] + 24))();
        printf("Plaintext: %s\n", *information[i]);
        LODWORD(info) = printf("Ciphertext: %s\n", *(information[i] + 8));
      }
    }
  }
  return info;
}

unsigned __int64
encrypt_string(void)
{
  int option; // [rsp+8h] [rbp-28h]
  char info[12]; // [rsp+Ch] [rbp-24h]
  char *msg; // [rsp+18h] [rbp-18h]
  void *key; // [rsp+20h] [rbp-10h]
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  print_encryption_menu();
  __isoc99_scanf("%d%*c", &option);
  *&info[4] = create_info();
  if ( *&info[4] )
  {
    if ( option == 1 )
    {
      *(*&info[4] + 16LL) = key_encrypt;
      *(*&info[4] + 24LL) = print_key;
    }
    else
    {
      if ( option != 2 )
      {
        puts("Not a valid choice");
        return __readfsqword(0x28u) ^ canary;
      }
      *(*&info[4] + 16LL) = xor_encrypt;
      *(*&info[4] + 24LL) = print_xor;
    }
    printf("How long is your message?\n>", &option);
    __isoc99_scanf("%d%*c", info);
    *(*&info[4] + 36LL) = ++*info;
    msg = malloc(*info);
    printf("Please enter your message: ", info);
    fgets(msg, *info, stdin);
    **&info[4] = msg;
    key = malloc(*info);
    *(*&info[4] + 8LL) = key;
    (*(*&info[4] + 16LL))(msg, key);            // interesting call
    printf("Your encrypted message is: %s\n", key);
  }
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64
remove_encrypted_string(void)
{
  int index; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter the index of the message that you want to remove: ");
  __isoc99_scanf("%d%*c", &index);
  if ( index >= 0 && index <= 19 && information[index] && *(information[index] + 32) != 1 )
  {
    *(information[index] + 32) = 1;
    free(*information[index]);
    free(*(information[index] + 8));
  }
  else
  {
    puts("Not a valid index.");
  }
  return __readfsqword(0x28u) ^ v2;
}

int __cdecl
main(int argc, const char **argv, const char **envp)
{
  int choice; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("What is your user id?");
  __isoc99_scanf("%d%*c", &user_id);
  while ( 1 )
  {
    print_menu();
    __isoc99_scanf("%d%*c", &choice);
    switch ( choice )
    {
      case 1:
        encrypt_string();
        break;
      case 2:
        remove_encrypted_string();
        break;
      case 3:
        view_messages();
        break;
      case 4:
        edit_encrypted_message();
        break;
      case 5:
        return 0;
      default:
        puts("Not a valid option");
        break;
    }
  }
}