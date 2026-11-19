"""Per-project configuration loader for DataPulse AST Debugger."""

import logging
import tomllib
from pathlib import Path
from typing import List, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DataPulseConfig(BaseModel):
    """Configuração por projeto lida de `.datapulse.yml`, `.datapulse.yaml` ou `pyproject.toml`."""

    ignore_paths: List[str] = Field(default_factory=list)
    disable_rules: List[str] = Field(default_factory=list)
    min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"
    complexity_threshold: int = 12
    sql_dialect: Optional[str] = None
    multi_finding: bool = True

    @classmethod
    def load(cls, target_path: Union[str, Path]) -> "DataPulseConfig":
        """Carrega configuração a partir do diretório alvo (ou pasta pai se for arquivo)."""
        path = Path(target_path).resolve()
        search_dir = path if path.is_dir() else path.parent

        for yaml_name in (".datapulse.yml", ".datapulse.yaml"):
            cfg_file = search_dir / yaml_name
            if cfg_file.is_file():
                try:
                    raw = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
                    if raw is None:
                        return cls()
                    if isinstance(raw, dict):
                        return cls(**raw)
                    logger.warning("Formato inválido em %s; usando configuração padrão.", cfg_file)
                except Exception as exc:
                    logger.warning("Falha ao ler %s: %s; usando configuração padrão.", cfg_file, exc)
                return cls()

        pyproject_file = search_dir / "pyproject.toml"
        if pyproject_file.is_file():
            try:
                with open(pyproject_file, "rb") as f:
                    data = tomllib.load(f)
                tool_cfg = data.get("tool", {}).get("datapulse")
                if isinstance(tool_cfg, dict):
                    return cls(**tool_cfg)
            except Exception as exc:
                logger.warning("Falha ao ler [tool.datapulse] em %s: %s", pyproject_file, exc)

        return cls()
