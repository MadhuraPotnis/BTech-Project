#!/usr/bin/env python
# coding: utf-8

# In[4]:


import pandas as pd
import numpy as np
from imblearn.over_sampling import SMOTE
from collections import Counter
from matplotlib import pyplot
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv (r'A:\BTech\BTech Project\Datasets\Initial_Signature_Dataset.csv')
columns= list(df.columns)

X = df[columns[:-1]]
y = df[['Label1']]

# label encode the target variable
y = LabelEncoder().fit_transform(y)

# summarize distribution before SMOTE
counter1 = Counter(y)
for p,r in counter1.items():
	per = r / len(y) * 100
	print('Class=%d, n=%d (%.3f%%)' % (p, r, per))
    
# plot the distribution
pyplot.bar(counter1.keys(), counter1.values())
pyplot.show()

# transform the dataset
oversample = SMOTE()
X, y = oversample.fit_resample(X, y)

# summarize distribution
counter = Counter(y)
for k,v in counter.items():
	per = v / len(y) * 100
	print('Class=%d, n=%d (%.3f%%)' % (k, v, per))
    
# plot the distribution
pyplot.bar(counter.keys(), counter.values())
pyplot.show()

data_res = pd.DataFrame(X)
data_res['Label1'] = y
data_res.to_csv(r'A:\BTech\BTech Project\Datasets\sample_smote_with_header.csv', index=False)


# In[ ]:




