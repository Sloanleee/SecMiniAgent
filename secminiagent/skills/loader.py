from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Skill:
    name: str
    description: str
    content: str


class SkillLoader:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.builtin_dir = Path(__file__).parent / "builtin"
        self.local_dir = cwd / ".secminiagent" / "skills"

    def load_all(self) -> list[Skill]:
        skills: list[Skill] = []
        for directory in [self.builtin_dir, self.local_dir]:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.md")):
                skills.append(self._load(path))
        return skills

    def select(self, prompt: str, forced: tuple[str, ...] = ()) -> list[Skill]:
        all_skills = self.load_all()
        if forced:
            wanted = set(forced)
            return [skill for skill in all_skills if skill.name in wanted]
        lowered = prompt.lower()
        selected = [
            skill
            for skill in all_skills
            if skill.name.replace("_", " ") in lowered or skill.name in lowered
        ]
        if "secret" in lowered or "credential" in lowered or "api key" in lowered:
            selected.extend(skill for skill in all_skills if skill.name == "secret_scan")
        if "dependency" in lowered or "requirements" in lowered or "package" in lowered:
            selected.extend(skill for skill in all_skills if skill.name == "dependency_audit")
        if "security" in lowered or "audit" in lowered or "review" in lowered:
            selected.extend(skill for skill in all_skills if skill.name == "code_security_review")
        unique: dict[str, Skill] = {}
        for skill in selected:
            unique[skill.name] = skill
        return list(unique.values())

    def _load(self, path: Path) -> Skill:
        content = path.read_text(encoding="utf-8")
        name = path.stem
        description = ""
        for line in content.splitlines():
            if line.startswith("# "):
                name = line[2:].strip() or name
            elif line.lower().startswith("description:"):
                description = line.split(":", 1)[1].strip()
                break
        return Skill(name=name, description=description or path.stem, content=content)
