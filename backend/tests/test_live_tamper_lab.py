import requests

r_presets = requests.get('http://127.0.0.1:8000/api/tamper-lab/presets')
print('Presets Status:', r_presets.status_code)
data_presets = r_presets.json()
print('Available Baselines:', [b['name'] for b in data_presets['baselines']])
print('Available Attacks:', [a['name'] for a in data_presets['attacks']])

r_exec = requests.post('http://127.0.0.1:8000/api/tamper-lab/execute', data={
    'attack_type': 'copy_move',
    'baseline_id': 'laptop_webcam'
})
print('\nExecute Tamper Lab Status:', r_exec.status_code)
d = r_exec.json()
print('Attack Applied:', d['attack_info']['name'])
print('Detection Successful:', d['detection_successful'])
print(f"Risk Score Transition: {d['baseline']['risk_score']}% -> {d['tampered']['risk_score']}%")
print(f"Verdict Transition: {d['baseline']['verdict']} -> {d['tampered']['verdict']}")
print('Fired Flags:')
for fl in d['tampered']['flags']:
    print(f"  • {fl}")
print('Metrics:', d['tampered']['metrics'])
