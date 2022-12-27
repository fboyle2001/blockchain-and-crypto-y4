import scipy.optimize as opt
import numpy as np
import matplotlib.pyplot as plt


points = [
    (1, 0.1346),
    (2, 0.1306),
    (3, 0.1297),
    (4, 0.1446),
    (5, 0.2184),
    (6, 5.0216),
    (7, 128.3011),
    (8, 801.9544),
    (9, 2368.5479)
]

difficulties = []
delta_times = []

for (x, y) in points:
    difficulties.append(x)
    delta_times.append(y)

print("Total duration", sum(delta_times))

difficulties = np.array(difficulties)
delta_times = np.array(delta_times)

(A, B), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties, delta_times)
print(A, B)

# Plot the exponentially fitted curve
x = np.linspace(0, max(difficulties), 1000)
y = A * np.exp(B * x)
plt.plot(x, y)

# Plot the original data points
plt.scatter(difficulties, delta_times, color="red")
plt.show()