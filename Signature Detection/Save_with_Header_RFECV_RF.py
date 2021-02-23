#!/usr/bin/env python
# coding: utf-8

# In[2]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_selection import RFECV

df = pd.read_csv (r'A:\BTech\BTech Project\Datasets\sample_smote_with_header.csv')
columns= list(df.columns)

X = df[columns[:-1]]
y = df[['Label1']]

# label encode the target variable
y = LabelEncoder().fit_transform(y)

rfc = RandomForestClassifier(random_state=101)
rfecv = RFECV(estimator=rfc, step=1, cv=StratifiedKFold(5), scoring='accuracy')
rfecv.fit(X, y)

print('Optimal number of features: {}'.format(rfecv.n_features_))

plt.figure(figsize=(16, 9))
plt.title('Recursive Feature Elimination with Cross-Validation', fontsize=18, fontweight='bold', pad=20)
plt.xlabel('Number of features selected', fontsize=14, labelpad=20)
plt.ylabel('% Correct Classification', fontsize=14, labelpad=20)
plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_, color='#303F9F', linewidth=3)

plt.show()
plt.imshow()

print(np.where(rfecv.support_ == False)[0])

data_res = pd.DataFrame(X)
data_res = data_res.drop(data_res.columns[np.where(rfecv.support_ == False)[0]], axis=1, inplace=False)
data_res['Label1'] = y
data_res.to_csv(r'A:\BTech\BTech Project\Datasets\features_selected_with_header.csv', index=False)


# In[ ]:




