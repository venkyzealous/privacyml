from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_replace
import numpy as np
from Pyfhel import Pyfhel, PyCtxt
import pandas as pd
from pyspark.sql.functions import udf
from pyspark.sql.types import BinaryType
import sys



#initialize HE
HE = Pyfhel()           # Creating empty Pyfhel object
ckks_params = {
    'scheme': 'CKKS',   # can also be 'ckks'
    'n': 2**14,         # Polynomial modulus degree. For CKKS, n/2 values can be
                        #  encoded in a single ciphertext.
                        #  Typ. 2^D for D in [10, 15]
    'scale': 2**30,     # All the encodings will use it for float->fixed point
                        #  conversion: x_fix = round(x_float * scale)
                        #  You can use this as default scale or use a different
                        #  scale on each operation (set in HE.encryptFrac)
    'qi_sizes': [60, 30, 30, 30, 60] # Number of bits of each prime in the chain.
                        # Intermediate values should be  close to log2(scale)
                        # for each operation, to have small rounding errors.
}
HE.contextGen(**ckks_params)  # Generate context for ckks scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
HE.rotateKeyGen()

def h_encrypt(ar_value): return HE.encryptPtxt(HE.encodeFrac(np.array([ar_value]))).to_bytes()
def h_decrypt(ar_value): return HE.decryptFrac(PyCtxt(pyfhel=HE,bytestring=bytes(ar_value),scheme='float')).tolist()[0]

sample_data =   [{"name": "John    D.", "balance":20.5,"credit":20.0},
                {"name": "Alice   G.", "balance": 25.0,"credit":20.0},
                {"name": "Bob  T.", "balance": 35.0,"credit":20.0},
                {"name": "Eve   A.", "balance": 28.5,"credit":20.0}]


sample_data = [{**item, 'balance_enc': h_encrypt(item['balance'])} for item in sample_data]
sample_data = [{**item, 'credit_enc': h_encrypt(item['credit'])} for item in sample_data]



df = pd.DataFrame(sample_data)
print('pandas data frame after encrypted data update')
print(df)



spark = SparkSession.builder.appName("Testing PySpark Example").getOrCreate()
sdf = spark.createDataFrame(df)
print('spark data frame')
sdf.show()



s_rdd = sdf.rdd
def add_fn (value1, value2):
    left = PyCtxt(pyfhel=HE,bytestring=bytes(value1),scheme='float') 
    right = PyCtxt(pyfhel=HE,bytestring=bytes(value2),scheme='float') 
    sum = left + right
    return sum.to_bytes()
s_rdd = s_rdd.map(lambda row: (row[0], row[1], row[2], add_fn(row[3], row[4])))
sdf = s_rdd.toDF(["name", "balance", "credit", "result_enc"])

print('spark data frame after encrypted data addition into result_enc')
sdf.show()

pd_result = sdf.toPandas().to_dict('records')
result_data = [{**item, 'result_dec': h_decrypt(item['result_enc'])} for item in pd_result]

print(pd.DataFrame(result_data))

