#!/usr/bin/env python
# coding: utf-8

# In[7]:


import random

'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

'''
Euclid's extended algorithm. when called with params a, b then a tuple is returned where
it is gcd, x value and y value where gcd=ax+by
'''
def extended_gcd(a,b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    
    #The lastremainder returned will consequentially be the gcd
    #the conditional statements simply serve to allow us to use this same function for both 
    #positive and negative values of a and b
    return lastremainder, lastx * (-1 if a< 0 else 1), lasty * (-1 if b < 0 else 1)

'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''
def mod_inverse(e, phi):
    ###At this stage we have d.e=1 mod phi. 
    #So we need to get d using the multiplicative inverse
    # using the formula d.e=1 mod m, we can use this function
    #to get d using the EEA.
    
    #mod_inverse(a,m) returns the inverse presuming a.c=1modm
    
    #note returning x%phi because a.c=1 mod m
    #a.c = e.x+phi.y=1 mod phi -----> phi.y mod phi give zero
    
    
    gcd, x, y = extended_gcd(phi, e)
    return y % phi

'''
Tests to see if a number is prime.
'''
def isPrime(p):
    if (p%2==0):
        return False
  
    k=4
    
    for i in range(1,k):
        a=random.randrange(2, p)
        #Use Euclid's Algorithm to verify that a and p are comprime
        g = gcd(a, p)
        while g != 1:
            a = random.randrange(2, p)
            g = gcd(a, p)
        if millerTest(p,a)==False: 
            return False
    
    print(p, " is possibly prime.")
    return True  

def millerTest(p, a):
    
    # Find p-1=r such that p-1 = 2^s * d 
    s=0
    d = p - 1;
    while (d % 2 == 0):
        s=s+1
        d //= 2;
 
    #If a^d=1mod p then p is possibly prime. Stop
    if (fastModularExponentiation(a,d,p)==1):
        return True
    
    #if a^(2^i) then p is possibly prime
    for i in range(0,s-1):
        if (fastModularExponentiation(a,(2**i)*d,p)==(p-1)):
            return True
        
    #if algortithm reached this step then p is composite
    return False    


def generate_keypair(p, q):
    if p == q:
        raise ValueError('p and q cannot be equal')
    
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    #d = multiplicative_inverse(e, phi)
    d=mod_inverse(e,phi)
    print(d)
    
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def fastModularExponentiation(a,b,m):
    #returns a^b mod m
    result=1
    
    while b>0:
        if b%2==0:
            a=(a**2)%m 
            b=b//2
        else:
            result=(a*result)%m
            b=b-1
    return result

def encrypt(pk, plaintext):
    #Unpack the key into it's components
    key, n = pk
    
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(fastModularExponentiation(ord(char), key, n)) for char in plaintext]

    #Return the array of bytes
    print(cipher)
    return cipher

def decrypt(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((fastModularExponentiation(char, key, n))) for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)
    
def decrypt_CRT(pk, cipher, p, q):
    key, n = pk
    plaintext=[]
    dp=key%(p-1)
    dq=key%(q-1)
    
    
    for char in cipher:
        mp=fastModularExponentiation(char, dp, p)
        mq=fastModularExponentiation(char, dq, q)
        
        _, yp, yq=extended_gcd(p, q)
        
        plaintext.append(chr(((mp*q*yq)+(mq*p*yp))%(p*q)))
    
    return ''.join(plaintext)

def nBitRandom(n):
    #generates a random number of n bits
    #ie it is a number between 0 and 2^n - 1
    return random.randrange(2**(n-1)+1, 2**n - 1)



if __name__ == '__main__':
    '''
    Detect if the script is being run directly by the user
    '''
    print ("RSA Encrypter/ Decrypter")
    
    n=int(input("Enter number of bits for p and q: "))
    p=nBitRandom(n)
    while (isPrime(p)==False):
        p=nBitRandom(n)

    q=nBitRandom(n)
    while ((isPrime(q)==False)):
        q=nBitRandom(n)

    print("p: ", p)

    print("q: ", q)
        
    print ("Generating your public/private keypairs now . . .")
    public, private = generate_keypair(p, q)
    print ("Your public key is ", public ," and your private key is ", private)
    message = input("Enter a message to encrypt with your private key: ")
    encrypted_msg = encrypt(private, message)
    print ("Your encrypted message is: ")
    print (''.join(map(lambda x: str(x), encrypted_msg)))
    print ("Decrypting message with public key (FME):", public ," . . .")
    print ("Your message is:")
    print (decrypt(public, encrypted_msg))
    
    print ("Decrypting message with public key (CRT):", public ," . . .")
    print ("Your message is:")
    print (decrypt_CRT(public, encrypted_msg, p, q))


# In[ ]:





# In[ ]:





# In[ ]:




