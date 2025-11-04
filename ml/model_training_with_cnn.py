import torch
import torch.nn as nn

class TraceCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(in_channels=1, out_channels=16, kernel_size=5),  # 16 filters, 5-window
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),  # réduction de dimension
            nn.Conv1d(16, 32, kernel_size=3),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),
            nn.Flatten(),
            nn.Linear(32 * 23, 64),  # dépend de la taille finale après pooling
            nn.ReLU(),
            nn.Linear(64, 2)  # classification binaire
        )

    def forward(self, x):
        x = x.unsqueeze(1)  # [batch_size, 1, trace_length]
        return self.cnn(x)

#Generation of the synthetic dataset
df = pd.read_csv("output/dataset.csv", header=None)
X = df.iloc[:, 1:].values
y = df.iloc[:, 0].values

#Convert to PyTorch tensor
X = torch.stack(X)
y = torch.tensor(y)

#Initialization of the model and training components
model = TraceCNN()
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
