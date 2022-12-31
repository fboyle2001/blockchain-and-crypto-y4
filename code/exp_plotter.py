import scipy.optimize as opt
import numpy as np
import matplotlib.pyplot as plt

data = {
    1: [0.1346, 0.1437, 0.1406, 0.1426],
    2: [0.1306, 0.2803, 0.2803, 0.2812], 
    3: [0.1297, 0.4300, 0.4219, 0.4318],
    4: [0.1446, 0.5935, 0.6154, 0.5944],
    5: [0.2184, 0.9805, 1.0342, 0.7589],
    6: [5.0216, 1.7843, 1.7593, 5.0764],
    7: [128.3011, 121.3415, 43.3940, 43.1945],
    8: [801.9544, 548.0938, 1375.4983, 840.1393],
    # 9: [2368.5479]
}

difficulties = []

min_delta_times = []
avg_delta_times = []
max_delta_times = []

for difficulty, times in data.items():
    difficulties.append(difficulty)
    min_dt = min(times)
    max_dt = max(times)
    avg_dt = sum(times) / len(times)

    min_delta_times.append(min_dt)
    avg_delta_times.append(avg_dt)
    max_delta_times.append(max_dt)

difficulties = np.array(difficulties)
min_delta_times = np.array(min_delta_times)
avg_delta_times = np.array(avg_delta_times)
max_delta_times = np.array(max_delta_times)
err_delta_times = np.array(list(zip(avg_delta_times - min_delta_times, max_delta_times - avg_delta_times))).T

excluded = None

(A_min, B_min), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:excluded], min_delta_times[:excluded]) # exclude last entry for now as we don't have enough data
(A_avg, B_avg), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:excluded], avg_delta_times[:excluded])
(A_max, B_max), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:excluded], max_delta_times[:excluded])

# Plot the exponentially fitted curve
def plot_exp_curve(A, B, color):
    x = np.linspace(0, max(10, max(difficulties)), 1000)
    y = A * np.exp(B * x)
    plt.plot(x, y, color=color)

plot_exp_curve(A_min, B_min, "green")
plot_exp_curve(A_avg, B_avg, "orange")
plot_exp_curve(A_max, B_max, "red")

# Plot the original data points
plt.xticks([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
plt.errorbar(difficulties, avg_delta_times, yerr=err_delta_times, color="blue", fmt=".", capsize=4) # type: ignore
plt.show()