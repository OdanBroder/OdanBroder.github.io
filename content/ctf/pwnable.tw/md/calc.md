## calc

### Let's check

![images](img/calc/main.png)

![images](img/calc/calc.png)

![images](img/calc/get_expr.png)
- Check if the expression valid.

There is nothing important in the above section; I will check the details in parse_expr.

```c
int __cdecl parse_expr(int input, _DWORD *arr)
{
  int v3; // eax
  int v4; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v6; // [esp+28h] [ebp-80h]
  int lenNum; // [esp+2Ch] [ebp-7Ch]
  char *num; // [esp+30h] [ebp-78h]
  int v9; // [esp+34h] [ebp-74h]
  _BYTE expression[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  v4 = input;
  v6 = 0;
  bzero(expression, 0x64u);                     // erases
  for ( i = 0; ; ++i )
  {
    if ( *(char *)(i + input) - (unsigned int)'0' > 9 )// check in [+, -, *, /, %] or null byte \(￣︶￣*\))
    {
      lenNum = i + input - v4;
      num = (char *)malloc(lenNum + 1);
      memcpy(num, v4, lenNum);
      num[lenNum] = 0;
      if ( !strcmp(num, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      v9 = atoi(num);
      if ( v9 > 0 )
      {
        v3 = (*arr)++;
        arr[v3 + 1] = v9;
      }
      if ( *(_BYTE *)(i + input) && *(char *)(i + 1 + input) - (unsigned int)'0' > 9 )// 
                                                // check if current index is not null and next index is not the num
                                                // if current index is null, continue
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      v4 = i + 1 + input;                       // next num
      if ( expression[v6] )
      {
        switch ( *(_BYTE *)(i + input) )
        {
          case '%':
          case '*':
          case '/':
            if ( expression[v6] != '+' && expression[v6] != '-' )// check in [%, *, /] -> calculate immediately
              goto LABEL_14;
            expression[++v6] = *(_BYTE *)(i + input);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(arr, expression[v6]);          // calculate the right first and replace with new sign
            expression[v6] = *(_BYTE *)(i + input);
            break;
          default:                              // it checks byte "\n" ~ mean end of input
            eval(arr, expression[v6--]);        // calculate the right first and remove this sign
            break;
        }
      }
      else
      {
        expression[v6] = *(_BYTE *)(i + input);
      }
      if ( !*(_BYTE *)(i + input) )
        break;
    }
  }
  while ( v6 >= 0 )
    eval(arr, expression[v6--]);
  return 1;
}
```

I comment in detail in some important code, so I just summarize the main note.

1. This function checks each char in input until this char is in [+, -, *, /, %] or a null byte. Why NULL byte?? 

The reason for this is that `- (unsigned int)'0'`
![images](img/calc/parse_expr_zero.png) 

2. If matched, it calls malloc and atoi to convert to a number. Especially, this saves the number of num to *arr and each num after this,arr while arr is v1[101] in the calc function.

- I imagine that v1[0] saves the number of num, and v1[1], v1[2],.... save each number after.

3. In the first expression, this function doesn't call anything; it just saves the first size to expression[].

4. The next work is the same as the above-mentioned steps, but now this will calculate

```c
      if ( expression[v6] )
      {
        switch ( *(_BYTE *)(i + input) )
        {
          case '%':
          case '*':
          case '/':
            if ( expression[v6] != '+' && expression[v6] != '-' )// check in [%, *, /] -> calculate immediately
              goto LABEL_14;
            expression[++v6] = *(_BYTE *)(i + input);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(arr, expression[v6]);          // calculate the right first and replace with new sign
            expression[v6] = *(_BYTE *)(i + input);
            break;
          default:                              // it checks byte "\n" ~ mean end of input
            eval(arr, expression[v6--]);        // calculate the right first and remove this sign
            break;
        }
      }
```

<p align="center">
  <img src="img/calc/eval.png" />
</p>

***eval***  only calculate two number `a1[*a1 - 1]` and `a1[*a1]` and give the result in the first number. After that, this will decrease `*a1 ~ the number of num` to get the index of the result and calculate later expression.

- This rule is that calculate [*, /, %] before [+, -]. This section implement by locating the sign with higher role in the right of expression.
- If sign in [*, /, %], and the previous also in this, this will calculate the previous first because of the same role. Meanwhile, if sign in [\*, /, %] and the previous in [+, -], this only add this sign to the right of expression.
- If sign in [+, -], it will calculate the right most of expression and replace the old sign.

***Example***

1+2\*3+4
&rarr;1
&rarr;1+2\*3
&rarr;1+6+4

1+2\*3\*4+5
&rarr;1+2\*3
&rarr;1+6\*4
&rarr;1+24+5

1\*2+3+4\*5
&rarr;1\*2
&rarr;2+3
&rarr;5+4\*5

1\*2+3+4\*5+6
&rarr;1\*2
&rarr;2+3
&rarr;5+4\*5
&rarr;5+20+6

Once done, this section will calculate from the right to the left of the expression; this would be right because the sign in the later expression is only in [+, -] or the sign with the higher role in the rightmost

```c
while ( v6 >= 0 )
    eval(arr, expression[v6--]);
```

### Exploitation

Hmm, do I miss something?

- I just think that this should only handle (check in loop) with sign instead of both sign and number.

- If it gets two numbers in v1 to calculate, is it possible to input only one number and trigger something?

- Is this use of v1[0] as a count and taking it as the index to calculate while num is just in the next location secure?

If I don't input any number before signing in the first expression.

```c
if ( sign == '+' )
{
    a1[*a1 - 1] += a1[*a1];
}
```

```c
if ( parse_expr(input, v1) )                // calculate expression
{
    printf("%d\n", v1[v1[0]]);
    fflush(stdout);
}
```

#### AAR

![images](img/calc/bug1.png)

`-5333956 ~ 0xffae9c3c`

count = 1 

&rarr; a1[count - 1] += a1[count] ***(a1[0] ~ count ; a1[1] = 400)***

&rarr; a1[0] = 1 + a1[1] = 1 + 400 = 401

&rarr; count = 401

#### AAW

![images](img/calc/bug2.png)


count = 1 

&rarr; a1[count - 1] += a1[count] ***(a1[0] ~ count ; a1[1] = 400)***

&rarr; a1[0] = 1 + a1[1] = 1 + 400 = 401

&rarr; count = 401

&rarr; a1[count - 1] += a1[count] ***(a1[0] ~ count ; a1[1] = 400)***

&rarr; a1[400] += a1[401] 

a1[401] = 1, the reason for this is that
```c
if ( v9 > 0 )
{
    v3 = (*arr)++;
    arr[v3 + 1] = v9;
}
```
#### Note

The other sign has the same logic bug, so I just use it to leak, write the payload, and execute this.

### Payload

[***solve.py***](https://github.com/BabyBroder/CTF/blob/pwnableTW/calc/solve.py)