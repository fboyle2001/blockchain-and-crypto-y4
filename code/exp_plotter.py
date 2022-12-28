import scipy.optimize as opt
import numpy as np
import matplotlib.pyplot as plt

data = {
    1: [0.1346, 0.1437],
    2: [0.1306, 0.2803], 
    3: [0.1297, 0.4300],
    4: [0.1446, 0.5935],
    5: [0.2184, 0.9805],
    6: [5.0216, 1.7843],
    7: [128.3011, 121.3415],
    8: [801.9544, 548.0938],
    9: [2368.5479]
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

(A_min, B_min), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:-1], min_delta_times[:-1]) # exclude last entry for now as we don't have enough data
(A_avg, B_avg), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:-1], avg_delta_times[:-1])
(A_max, B_max), _ = opt.curve_fit(lambda x, a, b: a * np.exp(b * x), difficulties[:-1], max_delta_times[:-1])

# Plot the exponentially fitted curve
def plot_exp_curve(A, B, color):
    x = np.linspace(0, max(difficulties), 1000)
    y = A * np.exp(B * x)
    plt.plot(x, y, color=color)

plot_exp_curve(A_min, B_min, "green")
plot_exp_curve(A_avg, B_avg, "orange")
plot_exp_curve(A_max, B_max, "red")

# Plot the original data points
plt.errorbar(difficulties, avg_delta_times, yerr=err_delta_times, color="blue", fmt=".", capsize=4) # type: ignore
plt.show()