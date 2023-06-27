import pandas as pd
from statsmodels.tsa.statespace.sarimax import SARIMAX

# Assume 'data' is a pandas Series or DataFrame of your DNP3 traffic,
# indexed by timestamp, and 'sensor_readings' is the column of sensor readings

# Fit the SARIMA model
model = SARIMAX(data['sensor_readings'], order=(
    p, d, q), seasonal_order=(P, D, Q, S))
model_fit = model.fit(disp=False)

# Generate synthetic data
synthetic_data = model_fit.predict(start=data.index[0], end=data.index[-1])

# Print the synthetic data
print(synthetic_data)
