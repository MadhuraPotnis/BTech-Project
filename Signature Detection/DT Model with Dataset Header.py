#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import pandas as pd

from sklearn import metrics
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split

df = pd.read_csv (r'A:\BTech\BTech Project\Datasets\features_selected_DT_with_header.csv')
columns= list(df.columns)

X = df[columns[:-1]]
y = df[['Label1']]

# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

clf = DecisionTreeClassifier()
clf = clf.fit(X_train,y_train)

y_pred = clf.predict(X_test)

#Model Accuracy
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))

recall = metrics.recall_score(y_test, y_pred, average = 'macro')
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test, y_pred, average = 'macro'))

print("False Negative Rate: ", 1 - recall)


# In[ ]:




