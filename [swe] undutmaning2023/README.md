# Blocky
**Kategori:** Reversing

`main()` ser ut såhär:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // rax
  char v5[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v6; // [rsp+98h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  srand(0x539u);
  printf("Submit your flag.\n");
  __isoc99_scanf("%s", v5);
  v3 = encode(v5);
  if ( !memcmp(v3, &flag, 0x1240uLL) )
    printf("Congratulations! You found the flag :D\n");
  else
    printf("Wrong flag :(\n");
  return 0;
}
```
Den sätter random seedet som används och ber sedan om en input sträng. Den skickar sedan den till `encode()` om jämför om resultatet är lika med `flag`. Vi vill alltså reversa `encode()` för att skapa inputen som spottar ut `flag`. 

`encode()` som ut som följande.
```c
_DWORD *__fastcall encode(const char *inp)
{
  __int64 v1; // rdx
  int y_res; // eax
  int v3; // edx
  unsigned __int64 x_res; // [rsp+38h] [rbp-68h]
  __int64 v6; // [rsp+40h] [rbp-60h]
  int inp_idx; // [rsp+4Ch] [rbp-54h]
  int out_idx; // [rsp+50h] [rbp-50h]
  int inplen; // [rsp+54h] [rbp-4Ch]
  _DWORD *mem; // [rsp+58h] [rbp-48h]
  char intset[48]; // [rsp+68h] [rbp-38h] BYREF
  unsigned __int64 v12; // [rsp+98h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  mem = malloc(0x1340uLL);
  std::set<int>::set(intset);
  inplen = strlen(inp);
  out_idx = 0;
  for ( inp_idx = 0; inp_idx < inplen; ++inp_idx )
  {
    x_res = x(inp[inp_idx]);
    v6 = v1;
    y_res = y(intset);
    mem[out_idx] = y_res;
    mem[out_idx + 1] = HIDWORD(x_res);
    mem[out_idx + 2] = v3;
    mem[out_idx + 3] = HIDWORD(v6);
    mem[y_res] = x_res;
    mem[v3] = v6;
    out_idx += 4;
  }
  std::set<int>::~set(intset);
  return mem;
}
```
Vi skapar alltså ett stort minnesområde `mem` och i slutet returnar vi det. Vi skapar också ett set av `int`s som endast används som argument till `y()`. Vi loopar igenom strängen som gavs som input och ger varje bokstav till `x()`, och returvärdet av det tillsammans med `y()` och några variabler som verkar odefinerade indexerar och sparas i minnesområdet. Låt oss först kolla i `y()`.
```c
__int64 __fastcall y(__int64 intset)
{
  char v1; // dl
  __int64 a; // [rsp+18h] [rbp-38h] BYREF
  __int64 b[4]; // [rsp+20h] [rbp-30h] BYREF
  char v5; // [rsp+40h] [rbp-10h]
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  a = (unsigned int)(rand() % 462 + 308);
  b[0] = (unsigned int)(rand() % 462 + 308);
  while ( std::set<int>::count(intset, &a) )
    LODWORD(a) = rand() % 462 + 308;
  b[3] = std::set<int>::insert(intset, &a);
  v5 = v1;
  while ( std::set<int>::count(intset, b) )
    LODWORD(b[0]) = rand() % 462 + 308;
  std::set<int>::insert(intset, b);
  return a;
}
```
Tl;dr är att den hittar två tal som genereras utifrån rand() och ser till att de inte redan finns i int-setet. Sedan lägger den till talen till setet och returnerar det första talet. Sido-effekter av funktionen är att setet förändras och random-statet påverkas.

`x()` ser ut så här, och kom ihåg att inputen till det alltid är en bokstav i vår input, så att kunna invertera `x()` kommer vara viktigt.
```c
unsigned __int64 __fastcall x(int n)
{
  int c; // eax
  int b; // [rsp+10h] [rbp-20h]
  int a; // [rsp+18h] [rbp-18h]

  a = rand() % (n + 129);
  b = a - rand() % (a - n) - n;
  c = rand();
  return __PAIR64__(b - c % b, c % b);
}
```
`__PAIR64__` kombinerar bara 2 st. 32-bitars tal till ett 64-bitars tal, där det första talet hamnar i de högsta bitsen. Det går att förutsäga `rand()` om vi simulerar allt som händer tidigare i programmet (och det går säkert att reversa det här) men det kändes som att det saknades information för att garanterat kunna invertera `x()`. Med tanke på de odefinerade variablerna i `encode()` testade vi att ändra returvärdet till 128-bitars istället för 64, och då hittade IDA mycket fler beräkningar som gjordes.
```c
unsigned __int128 __fastcall x(int n)
{
  int c; // eax
  unsigned __int128 result; // rax
  int b; // [rsp+14h] [rbp-1Ch]
  int a; // [rsp+18h] [rbp-18h]

  a = rand() % (n + 129);
  b = rand() % (a - n);
  c = rand();
  *(_QWORD *)&result = __PAIR64__(a - b - n - c % (a - b - n), c % (a - b - n));
  *((_QWORD *)&result + 1) = __PAIR64__(b, a);
  return result;
}
```
Det är inte världens finaste kod, men med lite algebra går det lätt att få fram `n` från de 4 32-bitars talen som finns sparade i resultatet.
```
x_0 = c % (a - b - n)
x_1 = a - b - n - c % (a - b - n)
x_2 = a
x_3 = b

x_1 + x_0 = a - b - n
n = -(x_1 + x_0 - x_2 + x_3)
```
Så om vi kan få ut det fulla returvärdet av `x()` kommer vi kunna återskapa `n` utan att ens behöva förutsäga `rand()`.

Med information om att `x()` returnerar ett 128-bitars värde ser huvudloopen i `encode()` ut så här:

```c
for ( inp_idx = 0; inp_idx < inplen; ++inp_idx )
{
    x_res = x(inp[inp_idx]);
    y_res = y(intset);
    mem[out_idx] = y_res;
    mem[out_idx + 1] = DWORD1(x_res);
    mem[out_idx + 2] = v2;
    mem[out_idx + 3] = HIDWORD(x_res);
    mem[y_res] = x_res;
    mem[v2] = DWORD2(x_res);
    out_idx += 4;
}
```
`v2` ser fortfarande odefinerad ut, men om man dyker ner i assembly-nivån ser man att det faktiskt är ett andra returvärde från `y()`; det andra talet den lägger till till setet. Det spelar dock ingen roll här. Loopen skriver 4 32-bitars tal i taget från början av filen och framåt, samt två extra tal som kan ligga lite var som helst senare i minnesområdet. Vi vill plocka ut alla delar av `x_res`, vilket kan göras ganska lätt. Se lösningsskript nedan.
```py
from struct import unpack
with open('blocked','rb') as f:
    f.seek(0x3060) # &flag
    nums = unpack('i'*0x4d0, f.read(0x4d0*4)) # 0x1340 bytes

flag = ''
for i in range(0, len(nums), 4):
    x_0 = nums[nums[i]]
    x_1 = nums[i+1]
    x_2 = nums[nums[i+2]]
    x_3 = nums[i+3]

    n = -(x_0 + x_1 + x_3 - x_2)
    flag += chr(n)
    if flag.endswith('}'): break
print(flag)
```
Vi får då flaggan `undut{dXBwIGRlIGhlbWxpZ2EgcmVjZXB0ZW4gb2NoIHZpZnRhciBuw7ZqdC4gS29tbWVyIG}`. 

Om någon är golfsugen kan man försöka slå det här:
```py
import struct;n=struct.unpack('i'*5770,open('blocked','rb').read()[12384:]);i=0
while i<292:print(end=chr(-(n[n[i]]+n[i+1]+n[i+3]-n[n[i+2]])));i+=4
```

Tycker själv det var lite synd att man inte egentligen behövde bry sig om `y()` eller `rand()` alls, vet inte om det var tanken från skaparen.

okej hejdå puss