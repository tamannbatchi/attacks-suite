
# This code takes a simulated trace as input
# and predicts the secret bit using the training model


import sys
import torch
import torch.nn as nn
import json

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

# Load of training model
model = TraceNet()
model.load_state_dict(torch.load("ml/model.pt"))
model.eval()

# Read of CSV file containing the traces
with open("output/Traces.csv", "r") as f:
  trace_str = f.readline()

trace = [float(x) for x in trace_str.strip().split(",")[1:]]

# Convert trace to PyTorch tensor
x = torch.tensor(trace).unsqueeze(0)
confidence = round(x.mean().item(), 4)

# Prediction
with torch.no_grad():
  output = model(x)
  predicted = torch.argmax(output, dim=1).item()
  print(predicted)

# Save of prediction in a JSON file
with open("output/predictions.json", "w") as f:
    json.dump({"bit": predicted, "confidence": confidence}, f)
