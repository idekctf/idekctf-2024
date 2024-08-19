from Crypto.Util.number import *

#Some magic from Willy Wonka
def chocolate_generator(m:int) -> int:
    p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
    return (pow(13, m, p) + pow(37, m, p)) % p

#The golden ticket is hiding inside chocolate
flag = b"idek{REDACTED}"
golden_ticket = bytes_to_long(flag)
flag_chocolate = chocolate_generator(golden_ticket)
chocolate_bag = []

#Willy Wonka is making chocolates
for i in range(golden_ticket):
    chocolate_bag.append(chocolate_generator(i))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-2:]

#Can you help Charles get the golden ticket?
print(remain)

#[88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247, 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242]