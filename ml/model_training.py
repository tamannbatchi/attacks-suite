
#This code trains a Deep Learning model
#to predict a secret bit form simulated traces

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim


#Definition of neural network model
class TraceNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(100, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        return self.fc(x)

#Generation of the synthetic dataset
df = pd.read_csv("output/dataset.csv", header=None)
X = df.iloc[:, 1:].values
y = df.iloc[:, 0].values

#Conversion to PyTorch tensor
X = torch.stack(X)
y = torch.tensor(y)

#Initialization of the model and training components
model = TraceNet()
optimizer = optim.Adam(model.parameters(), lr=0.001)
loss_fn = nn.CrossEntropyLoss()

#Loop over 20 training epochs
for epoch in range(20):
    out = model(X)
    loss = loss_fn(out, y)
    loss.backward()
    optimizer.step()
    optimizer.zero_grad()
    print(f"Epoch {epoch}: loss={loss.item():.4f}")

#Save of model
torch.save(model.state_dict(), "ml/model.pt")
