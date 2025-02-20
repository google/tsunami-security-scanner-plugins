import time
from pyspark.sql import SparkSession

# Initialize Spark session
spark = SparkSession.builder.appName("Fibonacci with Spark").getOrCreate()


# Function to calculate Fibonacci numbers
def fibonacci(n):
  a, b = 0, 1
  for _ in range(n):
    yield a
    a, b = b, a + b


# Create an RDD with the range of Fibonacci numbers to calculate
n = 10  # Number of Fibonacci numbers to generate
fibonacci_rdd = spark.sparkContext.parallelize(range(n))

# Calculate Fibonacci numbers using map transformation
fibonacci_result = fibonacci_rdd.map(lambda x: list(fibonacci(x)))

# Introduce a unlimit loop with a sleep time to keep spark WebUI running
# We actually dont' want to calculate fibonacci :)
while True:
  time.sleep(1)

# Collect and print the Fibonacci numbers
for result in fibonacci_result.collect():
  print(result)

# Stop the Spark session
spark.stop()
