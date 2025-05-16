import matplotlib.pyplot as plt

# Data from testing
window_sizes = [3, 5, 10, 15, 20, 25]
throughputs = [0.14, 0.27, 0.48, 0.76, 0.63, 0.66]

# configuration
plt.figure(figsize=(8, 5))
plt.plot(window_sizes, throughputs, marker='o', linestyle='-', color='blue', label='Throughput')

# Labels and title
plt.title('Effect of Window Size on Throughput')
plt.xlabel('Window Size')
plt.ylabel('Throughput (Mbps)')
plt.grid(True)
plt.xticks(window_sizes)  # Ensure all x-values are labeled
plt.legend()

# plot
plt.tight_layout()
plt.show()