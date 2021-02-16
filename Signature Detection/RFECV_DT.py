#!/usr/bin/env python
# coding: utf-8

# In[2]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_selection import RFECV

df = pd.read_csv (r'A:\BTech\BTech Project\Datasets\sample_smote.csv')
data = df.values

# split into input and output elements
X, y = data[:, :-1], data[:, -1]

# label encode the target variable
y = LabelEncoder().fit_transform(y)

rfc = DecisionTreeClassifier()
rfecv = RFECV(estimator=rfc, step=1, cv=StratifiedKFold(5), scoring='accuracy')
rfecv.fit(X, y)

print('Optimal number of features: {}'.format(rfecv.n_features_))

plt.figure(figsize=(16, 9))
plt.title('Recursive Feature Elimination with Cross-Validation', fontsize=18, fontweight='bold', pad=20)
plt.xlabel('Number of features selected', fontsize=14, labelpad=20)
plt.ylabel('% Correct Classification', fontsize=14, labelpad=20)
plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_, color='#303F9F', linewidth=3)

plt.show()

print(np.where(rfecv.support_ == False)[0])

data_res = pd.DataFrame(X)
data_res = data_res.drop(data_res.columns[np.where(rfecv.support_ == False)[0]], axis=1, inplace=False)
data_res['y'] = y
np.savetxt(r'A:\BTech\BTech Project\Datasets\features_selected_DT.csv', data_res, delimiter=",")


# In[ ]:




