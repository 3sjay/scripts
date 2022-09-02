## Call C from perl (no additional libs needed)
```
user@pc /tmp % cat a.pl 
#!/usr/bin/env perl
use strict;
use Inline C => << 'END_C';
void hello() {
  printf("hello world\n");
}
END_C

hello();
user@pc /tmp % perl a.pl 
hello world
``

