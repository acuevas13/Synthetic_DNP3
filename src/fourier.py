from scipy.signal import find_peaks
from scipy.fft import fft, ifft, fftfreq
import numpy as np
import matplotlib.pyplot as plt
from scipy.fft import fft, fftfreq, ifft

def fourier1():
    # Assume 'data' is a numpy array of your numerical datas
    data = [0,1,0,1,0,1,0,1,2,0,1,0,1,0,1,2,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,2,0,1,0,1,0,1,2]
    # Calculate the FFT and the frequencies
    yf = fft(data)
    xf = fftfreq(len(data))

    # Calculate the power spectrum
    power = np.abs(yf)**2

    # Plot the power spectrum
    plt.plot(xf, power)
    plt.show()

    # Identify the dominant frequencies
    # This is a simple example where we just choose the highest 5 frequencies
    # In reality, you might want to use a more sophisticated method
    dominant_freqs = np.argsort(power)[-5:]

    # Generate synthetic data
    # synthetic_data = np.zeros_like(data)
    synthetic_data = np.zeros_like(data, dtype=float)  # Define as a float array
    for freq in dominant_freqs:
        amplitude = np.abs(yf[freq])
        phase = np.angle(yf[freq])
        synthetic_data += amplitude * np.cos(2 * np.pi * freq * xf + phase)

    # Print the synthetic data
    print(f"synthetic_data: {synthetic_data}")


    # Suppose you have a mapping of DNP3 message types to numbers
    msg_to_num = {'read': 0, 'response': 1, 'confirm': 2, 'select': 3, 'operate': 4, }
    num_to_msg = {v: k for k, v in msg_to_num.items()}  # Reverse mapping

    # After generating synthetic_data, convert it back to DNP3 messages
    synthetic_data_messages = [num_to_msg[round(num)] for num in synthetic_data]

    # Print the synthetic data
    print(f"synthetic_data_messages: {synthetic_data_messages}")


def f2(data, n_freqs=5):
    # Step 1: Perform Fourier Transform
    n = len(data)
    yf = fft(data)
    xf = fftfreq(n)

    # Step 2: Identify dominant frequencies
    power_spectrum = np.abs(yf)**2
    peaks, _ = find_peaks(power_spectrum)
    # Sort by power and keep top n_freqs frequencies
    dominant_freqs = peaks[np.argsort(-power_spectrum[peaks])[:n_freqs]]

    # Step 3: Generate synthetic data
    synthetic_data = np.zeros_like(data, dtype=float)
    for freq in dominant_freqs:
        amplitude = np.abs(yf[freq]) / n
        phase = np.angle(yf[freq])
        synthetic_data += amplitude * np.cos(2 * np.pi * freq * xf + phase)

    # Step 4: Normalize synthetic data to range of original data
    synthetic_data = (synthetic_data - np.min(synthetic_data)) / \
        (np.max(synthetic_data) - np.min(synthetic_data))
    synthetic_data = synthetic_data * \
        (np.max(data) - np.min(data)) + np.min(data)

    # Step 5: Convert synthetic data back to discrete states
    synthetic_data = np.round(synthetic_data).astype(int)
    print(f"synthetic_data: {synthetic_data}")

    return synthetic_data

data = [0,1,0,1,0,1,0,1,2,0,1,0,1,0,1,2,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,2,0,1,0,1,0,1,2]

f2(data)
