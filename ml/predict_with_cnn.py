import torch
import torch.nn as nn
import json

# Definition of CNN model
class TraceCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(1, 16, kernel_size=5),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),
            nn.Conv1d(16, 32, kernel_size=3),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),
            nn.Flatten(),
            nn.Linear(32 * 23, 64),  
            nn.ReLU(),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        x = x.unsqueeze(1)  # [batch_size, 1, trace_length]
        return self.cnn(x)

#Load of trained model
model = TraceCNN()
model.load_state_dict(torch.load("ml/model.pt"))
model.eval()

# Read of the trace
with open("output/Traces.csv", "r") as f:
    trace_str = f.readline()
    trace = [float(x) for x in trace_str.strip().split(",")[1:]]

# Convert to tensor
x = torch.tensor(trace, dtype=torch.float32).unsqueeze(0)  # [1, trace_length]
confidence = round(x.mean().item(), 4)

# Prediction
with torch.no_grad():
    output = model(x)
    predicted = torch.argmax(output, dim=1).item()
    print(predicted)

# Save JSON
with open("output/predictions.json", "w") as f:
    json.dump({"bit": predicted, "confidence": confidence}, f)
