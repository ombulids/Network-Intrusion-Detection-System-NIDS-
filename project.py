import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'attack', 'level'
]
df = pd.read_csv("KDDTrain+.txt", header=None, names=columns)
print("Shape of dataset:", df.shape)
df['attack'] = df['attack'].str.strip()
df['attack'] = df['attack'].apply(lambda x: 0 if x == 'normal' else 1)
label_encoder = LabelEncoder()
print(label_encoder)
df['protocol_type'] = label_encoder.fit_transform(df['protocol_type'])
df['service'] = label_encoder.fit_transform(df['service'])
df['flag'] = label_encoder.fit_transform(df['flag'])
X = df.iloc[:,0:41]
y = df['attack']
Xtrain , Xtest, ytrain , ytest = train_test_split(X,y,random_state=11,test_size=0.2)
rf = RandomForestClassifier()
rf.fit(Xtrain,ytrain)
y_pred = rf.predict(Xtest)
print(rf.score(Xtest,ytest))
print(classification_report(ytest,y_pred))
print(f"Prediction of First Package:{y_pred[0]}")
joblib.dump(rf ,'Model(Nids)')
