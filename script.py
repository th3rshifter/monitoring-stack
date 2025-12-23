num = int(input())
last_digit = num % 10
first_digit = (num // 10) % 10
second_digit = num // 100

print(last_digit, first_digit, second_digit)

sum_digit = (last_digit + first_digit + second_digit)
multi_digit = (last_digit * first_digit * second_digit)

print('Сумма цифр =', sum_digit)
print('Произведение цифр =', multi_digit)

#test