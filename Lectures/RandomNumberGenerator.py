import hashlib
import random
import matplotlib.pyplot as plt


def hash_function(r):
    return hashlib.sha256(str(r).encode()).hexdigest()


def roll_die(n):
    return random.randint(1, n)


def protocol(n: int):
    # Step 2: Harm picks a random integer r from 1 to 20 (inclusive) and computes d = h(r).
    r = roll_die(n)
    d = hash_function(r)

    # Step 3: Alex picks a random integer a from 1 to 20 (inclusive).
    a = roll_die(n)

    # Step 4: Harm reveals r to Alex.

    # Step 5: Alex verifies that h(r) = d. If not, Alex aborts the protocol because Harm cheated.
    if hash_function(r) != d:
        return None

    # Step 6: The result of the die roll is (r + a) mod 20 + 1.
    return (r + a) % n + 1


def main():
    n = 20
    runs = 100000
    # Simulate the protocol 10000 times
    results = [protocol(n) for _ in range(100000)]

    # Plot the results
    plt.hist(results, bins=range(1, n + 2), align='left', rwidth=0.8)
    plt.xticks(range(1, n + 1))
    plt.xlabel('Die Roll Result')
    plt.ylabel('Frequency')
    plt.title('Distribution of Die Roll Results in 100000 Simulations of the Protocol')

    # Save the plot to a file
    plt.savefig('die_roll_results.png')

    plt.show()


if __name__ == '__main__':
    main()
