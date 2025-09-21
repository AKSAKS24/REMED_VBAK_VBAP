from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re

app = FastAPI()


class Payload(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    code: str


class ResponseModel(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    original_code: str
    remediated_code: str


def process_abap_code(payload: Payload):
    code = payload.code
    original_code = code
    today_str = datetime.now().strftime("%Y-%m-%d")
    tag = f"\"Added By Pwc {today_str},"

    remediated_code = code

    # --- Case 1: Replace field references VBUK-field or VBUK~field → VBAK
    pattern_vbuk_field = re.compile(r'\bvbuk([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_vbuk_field.sub(
        lambda m: f"vbak{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 2: Replace field references VBUP-field or VBUP~field → VBAP
    pattern_vbup_field = re.compile(r'\bvbup([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_vbup_field.sub(
        lambda m: f"vbap{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 3: Replace field references VBTYP-field or VBTYP~field → VBTYPL
    pattern_vbtyp_field = re.compile(r'\bvbtyp([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_vbtyp_field.sub(
        lambda m: f"vbtypl{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 4: Replace standalone table/type references VBUK → VBAK
    pattern_vbuk_table = re.compile(r'\bvbuk\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_vbuk_table.sub(
        lambda m: f"VBAK {tag}", remediated_code
    )

    # --- Case 5: Replace standalone table/type references VBUP → VBAP
    pattern_vbup_table = re.compile(r'\bvbup\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_vbup_table.sub(
        lambda m: f"VBAP {tag}", remediated_code
    )

    # --- Case 6: Replace standalone table/type references VBTYP → VBTYPL
    pattern_vbtyp_table = re.compile(r'\bvbtyp\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_vbtyp_table.sub(
        lambda m: f"VBTYPL {tag}", remediated_code
    )

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=remediated_code,
    )


@app.post('/remediate_abap', response_model=ResponseModel)
async def remediate_abap(payload: Payload):
    return process_abap_code(payload)
