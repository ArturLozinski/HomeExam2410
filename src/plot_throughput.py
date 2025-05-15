import matplotlib.pyplot as plt

# Data from your table
window_sizes = [3, 5, 10, 15, 20, 25]
throughputs = [0.1, 0.11, 0.16, 0.25, 0.27, 0.2]

# Plot configuration
plt.figure(figsize=(8, 5))
plt.plot(window_sizes, throughputs, marker='o', linestyle='-', color='blue', label='Throughput')

# Labels and title
plt.title('Effect of Window Size on Throughput')
plt.xlabel('Window Size')
plt.ylabel('Throughput (Mbps)')
plt.grid(True)
plt.xticks(window_sizes)  # Ensure all x-values are labeled
plt.legend()

# Show the plot
plt.tight_layout()
plt.show()