import logging
from typing import Dict, Tuple, Union

logger = logging.getLogger("Rex.Monitor.Validator")


class SensorRangeValidator:
    """
    Validates that sensor readings are within physical, plausible bounds.
    Configurable by passing in target valid range tuples.
    """

    def __init__(self, valid_ranges: Dict[Union[str, int], Tuple[float, float]] = None):
        # Default fallback ranges if none configured
        self.ranges = valid_ranges if valid_ranges is not None else {
            "soil_moisture":    (0.0, 100.0),
            "temperature":      (-20.0, 80.0),
            "humidity":         (0.0, 100.0),
            "irrigation_valve": (0.0, 1.0),
            "weather_station":  (-60.0, 80.0),
        }

    def validate(self, sensor_type: Union[str, int], value: float) -> bool:
        # Standardize strings
        key = str(sensor_type).lower()
        if key not in self.ranges:
            # Let unknown sensor types pass through
            return True
            
        low, high = self.ranges[key]
        if not (low <= value <= high):
            logger.warning(
                f"[RANGE VIOLATION] Sensor type '{sensor_type}' reading '{value}' was outside bounds [{low}, {high}]."
            )
            return False
        return True
