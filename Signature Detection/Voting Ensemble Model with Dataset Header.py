#!/usr/bin/env python
# coding: utf-8

# In[7]:


import numpy as np
import pandas as pd

from sklearn import metrics
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split

df_RF = pd.read_csv (r'A:\BTech\BTech Project\Datasets\features_selected_with_header.csv')
columns_RF = list(df_RF.columns)

X_RF = df_RF[columns_RF[:-1]]
y_RF = df_RF[['Label1']]

df_DT = pd.read_csv (r'A:\BTech\BTech Project\Datasets\features_selected_DT_with_header.csv')
columns_DT = list(df_DT.columns)

X_DT = df_DT[columns_DT[:-1]]
y_DT = df_DT[['Label1']]

# Split dataset into training set and test set
X_train_DT, X_test_DT, y_train_DT, y_test_DT = train_test_split(X_DT, y_DT, test_size=0.2)
X_train_RF, X_test_RF, y_train_RF, y_test_RF = train_test_split(X_RF, y_RF, test_size=0.2)

clf1 = RandomForestClassifier(n_estimators=200, random_state=0)
clf2 = DecisionTreeClassifier()
clf3 = GradientBoostingClassifier(max_depth = 10)
clf4 = AdaBoostClassifier(base_estimator = DecisionTreeClassifier(max_depth = 10))

clf1 = clf1.fit(X_train_RF,y_train_RF)
clf2 = clf2.fit(X_train_DT,y_train_DT)
clf3 = clf3.fit(X_train_DT,y_train_DT)
clf4 = clf4.fit(X_train_DT,y_train_DT)

y_pred_RF = clf1.predict(X_test_RF)
w1 = metrics.accuracy_score(y_test_RF, y_pred_RF)*100
print("Random Forest Accuracy - w1:",w1)
recall = metrics.recall_score(y_test_RF, y_pred_RF, average = 'macro')*100
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test_RF, y_pred_RF, average = 'macro')*100)
print("False Negative Rate: ", (1 - recall)*100)
print("---------------------------------------------------------------------")

y_pred_DT = clf2.predict(X_test_DT)
w2 = metrics.accuracy_score(y_test_DT, y_pred_DT)*100
print("Decision Tree Accuracy - w2:",w2)
recall = metrics.recall_score(y_test_DT, y_pred_DT, average = 'macro')*100
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test_DT, y_pred_DT, average = 'macro')*100)
print("False Negative Rate: ", (1 - recall)*100)
print("---------------------------------------------------------------------")

y_pred_DT = clf3.predict(X_test_DT)
w3 = metrics.accuracy_score(y_test_DT, y_pred_DT)*100
print("Gradient Boosting Accuracy - w3:",w3)
recall = metrics.recall_score(y_test_DT, y_pred_DT, average = 'macro')*100
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test_DT, y_pred_DT, average = 'macro')*100)
print("False Negative Rate: ", (1 - recall)*100)
print("---------------------------------------------------------------------")

y_pred_DT = clf4.predict(X_test_DT)
w4 = metrics.accuracy_score(y_test_DT, y_pred_DT)*100
print("AdaBoost Accuracy- w4:",w4)
recall = metrics.recall_score(y_test_DT, y_pred_DT, average = 'macro')*100
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test_DT, y_pred_DT, average = 'macro')*100)
print("False Negative Rate: ", (1 - recall)*100)
print("---------------------------------------------------------------------")

eclf = VotingClassifier(estimators=[('rf',clf1),('dt',clf2),('gb',clf3),('adb',clf4)], voting = 'soft', weights = [w1, w2, w3, w4])
eclf = eclf.fit(X_train_RF,y_train_RF)

y_pred_RF = eclf.predict(X_test_RF)

#Model Accuracy
print("Accuracy of ensemble:",metrics.accuracy_score(y_test_RF, y_pred_RF)*100)

recall = metrics.recall_score(y_test_RF, y_pred_RF, average = 'macro')*100
print("Recall: ", recall)
print("Precision score: ", metrics.precision_score(y_test_RF, y_pred_RF, average = 'macro')*100)

print("False Negative Rate: ", (1 - recall)*100)


# In[ ]:




