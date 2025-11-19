sweagent run \
  --config config/fuzz_atheris.yaml \
  --env.repo.github_url=https://github.com/SWE-agent/test-repo \
  --env.deployment.image=python:3.10 \
  --env.deployment.image=buildpack-deps:bookworm \
  --problem_statement.text="Try to fuzz some Python functions that might be fragile using fuzz_atheris to add some test cases to pytest.I'm running missing_colon.py as follows: division(23, 0). but I get the following error: File "/Users/fuchur/Documents/24/git_sync/swe-agent-test-repo/tests/./missing_colon.py", line 4 def division(a: float, b: float) -> float SyntaxError: invalid syntax" 

sweagent run \ 
  --config config/fuzz_atheris.yaml \
  --problem_statement.text="Try to fuzz some Python functions that might be fragile using fuzz_atheris to add some test cases to pytest.I'm running missing_colon.py as follows: division(23, 0). but I get the following error: File "/Users/fuchur/Documents/24/git_sync/swe-agent-test-repo/tests/./missing_colon.py", line 4 def division(a: float, b: float) -> float SyntaxError: invalid syntax"
  --env.repo.path=test-repo \
  --env.deployment.image=buildpack-deps:bookworm