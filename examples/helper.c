extern char str_buffer[100];
extern long long bss_number;

int str_in_buffer_len() {
    int i = 0;

    for (; i < 100; ++i) {
        if (str_buffer[i] == '\0')
            break;
    }

    return i;
}

void number_to_str() {
    long long number = bss_number;
    int steps = 0;

    while (number > 0) {
        long long digit_num = number % 10;
        number /= 10;

        char digit_chr = digit_num + '0';
        str_buffer[steps] = digit_chr;
        ++steps;
    }

    int l = 0;
    int r = steps - 1;

    while (l < r) {
        char tmp = str_buffer[l];
        str_buffer[l] = str_buffer[r]; 
        str_buffer[r] = tmp;

        ++l;
        --r;
    }
}
