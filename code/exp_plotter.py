import scipy.optimize as opt
import numpy as np
import matplotlib.pyplot as plt

data = {
    1: [0.1468, 0.1437, 0.1406, 0.1426, 0.1381],
    2: [0.2854, 0.2803, 0.2803, 0.2812, 0.2788], 
    3: [0.4300, 0.4300, 0.4219, 0.4318, 0.4244],
    4: [0.6448, 0.5935, 0.6154, 0.5944, 0.5839],
    5: [1.0125, 0.9805, 1.0342, 0.7589, 0.7854],
    6: [5.0216, 1.7843, 1.7593, 5.0764, 5.2126],
    7: [128.3011, 121.3415, 43.3940, 43.1945, 34.4185],
    8: [801.9544, 548.0938, 1375.4983, 840.1393, 924.8783],
    # 9: [2368.5479, 925.0658]
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

print(avg_delta_times)
plot_exp_curve(A_min, B_min, "green")
plot_exp_curve(A_avg, B_avg, "orange")
plot_exp_curve(A_max, B_max, "red")

# Plot the original data points
plt.xticks([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
plt.xlabel("Difficulty")
plt.ylabel("Time Taken (s)")
plt.errorbar(difficulties, avg_delta_times, yerr=err_delta_times, color="blue", fmt=".", capsize=4) # type: ignore
plt.legend(
    [
        f"y = {A_min:.4E} * exp({B_min:.4f}x)",
        f"y = {A_avg:.4E} * exp({B_avg:.4f}x)",
        f"y = {A_max:.4E} * exp({B_max:.4f}x)"
    ]
)
plt.show()

hash_rate = 4199376

diffs = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

for difficulty in range(1, 11):
    expected = A_avg * np.exp(B_avg * difficulty)
    max_ = A_max * np.exp(B_max * difficulty)
    min_ = A_min * np.exp(B_min * difficulty)

    pm = max(max_ - expected, expected - min_)

    hash_expected = hash_rate * expected
    hash_pm = hash_rate * pm

    print(difficulty, f"{expected:.4f}+{pm:.4f}", f"{hash_expected:.3E}+{hash_pm:.3E}")
