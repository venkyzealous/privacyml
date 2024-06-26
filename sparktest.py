from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_replace

# Create a SparkSession
spark = SparkSession.builder.appName("Testing PySpark Example").getOrCreate()

sample_data = [{"name": "John    D.", "age": 30},
  {"name": "Alice   G.", "age": 25},
  {"name": "Bob  T.", "age": 35},
  {"name": "Eve   A.", "age": 28}]

df = spark.createDataFrame(sample_data)

# Remove additional spaces in name
def remove_extra_spaces(df, column_name):
    # Remove extra spaces from the specified column
    df_transformed = df.withColumn(column_name, regexp_replace(col(column_name), "\\s+", " "))

    return df_transformed

transformed_df = remove_extra_spaces(df, "name")

transformed_df.show()

